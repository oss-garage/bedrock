// SPDX-License-Identifier: GPL-2.0
/*
 * Bedrock paravirtual batch console + tty guest module.
 *
 * The guest normally logs through the emulated 8250 UART (console=ttyS0).
 * That driver pokes the transmit-holding register one byte at a time, and
 * every OUT to port 0x3F8 is an unconditional VMX I/O exit — so console
 * output costs one VM exit per byte, and the UART FIFO doesn't help because
 * the 8250 driver still issues one OUT per byte.
 *
 * This module funnels *all* console traffic — kernel printk AND userspace
 * writes to /dev/console — through a single 4KB page shared with the
 * hypervisor, shipped one buffer per VMCALL (HYPERCALL_SERIAL_WRITE). The
 * host copies the bytes into the same serial sink the 8250 emulation feeds,
 * so output is captured identically — but at roughly one VM exit per line
 * instead of one per byte.
 *
 * Two registrations, modelled on the kernel's minimal ttynull driver
 * (drivers/tty/ttynull.c):
 *   - a `struct console` named "hvc" / index 0 whose `.write` batches printk
 *     records, matched by `console=hvc0` on the cmdline;
 *   - a tty driver whose `.write` batches userspace output. The console's
 *     `.device` callback returns this tty driver, so /dev/console routes to
 *     it and userspace output is batched too.
 *
 * Both paths funnel through bedrock_emit(), which also expands '\n' to
 * "\r\n" (matching what the old 8250 console did via uart_console_write) so
 * captured output keeps conventional CRLF line endings. The tty runs with
 * output post-processing disabled (c_oflag = 0) so the line discipline hands
 * us the raw buffer in one chunk and we do the CRLF expansion exactly once.
 *
 * The console is registered WITHOUT CON_PRINTBUFFER: earlyprintk=serial
 * already delivered the pre-registration boot log through the 8250, so we
 * take over from the current ring-buffer head rather than replaying it.
 *
 * This is output only — there is no input/get_chars path. The interactive
 * fallback shell in the initrd keeps using /dev/ttyS0 (the 8250 tty, which
 * does carry host-fed serial input).
 *
 * Hypervisor side: see crates/bedrock-vmx/src/exits/vmcall.rs
 * (HYPERCALL_SERIAL_REGISTER_PAGE / HYPERCALL_SERIAL_WRITE).
 */

#include <linux/console.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_port.h>
#include <linux/types.h>

#include "libvmcall.h"

#define BEDROCK_CONSOLE_PAGE_SIZE 4096U

/*
 * Shared page handed to the hypervisor. Both the console `.write` (printk)
 * and the tty `.write` (userspace) copy bytes here, then VMCALL the count.
 *
 * A lock IS required here, unlike a console-only design: the tty `.write`
 * runs in process context with no console_lock held, while the console
 * `.write` runs under console_lock (possibly from IRQ/printk context), so
 * the two could otherwise clobber the page. `page_lock` (taken irqsave)
 * serializes every access. The VMCALL is issued under the lock; the
 * hypervisor handler returns synchronously to the same guest RIP even if it
 * drains to userspace, so there is no re-entrancy on the guest side.
 */
static void *shared_page;
static DEFINE_SPINLOCK(page_lock);

/* Flush the staged `fill` bytes in the shared page to the hypervisor. */
static inline void bedrock_flush(unsigned int fill)
{
	if (fill)
		vmcall_serial_write(fill);
}

/*
 * Emit `count` bytes, expanding '\n' to "\r\n", staging into the shared page
 * and issuing one HYPERCALL_SERIAL_WRITE per page-full (records and tty
 * writes are normally well under a page, so this is one VMCALL per call).
 * Serialized by page_lock against the other write path.
 */
static void bedrock_emit(const char *buf, unsigned int count)
{
	char *page = shared_page;
	unsigned long flags;
	unsigned int i;
	unsigned int fill = 0;

	if (!page)
		return;

	spin_lock_irqsave(&page_lock, flags);
	for (i = 0; i < count; i++) {
		char ch = buf[i];

		if (ch == '\n') {
			/* Need room for the two-byte "\r\n". */
			if (fill + 2 > BEDROCK_CONSOLE_PAGE_SIZE) {
				bedrock_flush(fill);
				fill = 0;
			}
			page[fill++] = '\r';
			page[fill++] = '\n';
		} else {
			if (fill + 1 > BEDROCK_CONSOLE_PAGE_SIZE) {
				bedrock_flush(fill);
				fill = 0;
			}
			page[fill++] = ch;
		}
	}
	bedrock_flush(fill);
	spin_unlock_irqrestore(&page_lock, flags);
}

/* ---- printk console ---- */

static struct tty_driver *bedrock_tty_driver;

static void bedrock_console_write(struct console *co, const char *s,
				  unsigned int count)
{
	bedrock_emit(s, count);
}

static struct tty_driver *bedrock_console_device(struct console *co,
						 int *index)
{
	*index = 0;
	return bedrock_tty_driver;
}

/*
 * Name "hvc" + index 0 matches `console=hvc0`. No flags set here:
 * register_console() applies CON_ENABLED/CON_CONSDEV itself on the cmdline
 * match. CON_PRINTBUFFER is omitted so we start at the current ring-buffer
 * head (no replay of the earlyprintk boot log). `.device` makes /dev/console
 * route to our tty so userspace output is batched too.
 */
static struct console bedrock_console = {
	.name   = "hvc",
	.write  = bedrock_console_write,
	.device = bedrock_console_device,
	.flags  = 0,
	.index  = 0,
};

/* ---- userspace tty ---- */

static const struct tty_port_operations bedrock_tty_port_ops;
static struct tty_port bedrock_tty_port;

static int bedrock_tty_open(struct tty_struct *tty, struct file *filp)
{
	return tty_port_open(&bedrock_tty_port, tty, filp);
}

static void bedrock_tty_close(struct tty_struct *tty, struct file *filp)
{
	tty_port_close(&bedrock_tty_port, tty, filp);
}

static void bedrock_tty_hangup(struct tty_struct *tty)
{
	tty_port_hangup(&bedrock_tty_port);
}

static ssize_t bedrock_tty_write(struct tty_struct *tty, const u8 *buf,
				 size_t count)
{
	bedrock_emit((const char *)buf, (unsigned int)count);
	return count;
}

static unsigned int bedrock_tty_write_room(struct tty_struct *tty)
{
	/* We drain synchronously in .write, so there is always room. */
	return BEDROCK_CONSOLE_PAGE_SIZE;
}

static const struct tty_operations bedrock_tty_ops = {
	.open       = bedrock_tty_open,
	.close      = bedrock_tty_close,
	.hangup     = bedrock_tty_hangup,
	.write      = bedrock_tty_write,
	.write_room = bedrock_tty_write_room,
};

static int __init bedrock_console_init(void)
{
	struct tty_driver *driver;
	__u64 rc;
	int ret;

	shared_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!shared_page)
		return -ENOMEM;

	/*
	 * Register the page before anything can write to it (register_console
	 * below may flush immediately).
	 */
	rc = vmcall_serial_register_page(shared_page);
	if (rc != VMCALL_OK) {
		pr_err("bedrock-console: HYPERCALL_SERIAL_REGISTER_PAGE failed: %#llx\n",
		       rc);
		free_page((unsigned long)shared_page);
		shared_page = NULL;
		return -EIO;
	}

	/*
	 * Minimal console tty, modelled on drivers/tty/ttynull.c. One line,
	 * unnumbered node (reached via /dev/console, not a /dev/hvc0 node).
	 * Output post-processing is disabled (c_oflag = 0) because bedrock_emit
	 * does the '\n' -> "\r\n" expansion itself — leaving OPOST/ONLCR on
	 * would double-expand into "\r\r\n".
	 */
	driver = tty_alloc_driver(1,
				  TTY_DRIVER_RESET_TERMIOS |
				  TTY_DRIVER_REAL_RAW |
				  TTY_DRIVER_UNNUMBERED_NODE);
	if (IS_ERR(driver)) {
		ret = PTR_ERR(driver);
		goto err_unregister_page;
	}

	tty_port_init(&bedrock_tty_port);
	bedrock_tty_port.ops = &bedrock_tty_port_ops;

	driver->driver_name = "bedrock_console";
	driver->name = "hvc";
	driver->type = TTY_DRIVER_TYPE_CONSOLE;
	driver->init_termios = tty_std_termios;
	driver->init_termios.c_oflag = 0;
	tty_set_operations(driver, &bedrock_tty_ops);
	tty_port_link_device(&bedrock_tty_port, driver, 0);

	ret = tty_register_driver(driver);
	if (ret < 0) {
		tty_driver_kref_put(driver);
		tty_port_destroy(&bedrock_tty_port);
		goto err_unregister_page;
	}
	bedrock_tty_driver = driver;

	register_console(&bedrock_console);

	pr_info("bedrock-console: registered page=%p as console hvc0 (batch console + tty)\n",
		shared_page);
	return 0;

err_unregister_page:
	/*
	 * No deregister hypercall exists; dropping shared_page means the host
	 * simply never receives another SERIAL_WRITE. Free the page last.
	 */
	free_page((unsigned long)shared_page);
	shared_page = NULL;
	return ret;
}

static void __exit bedrock_console_exit(void)
{
	/*
	 * Order matters: unregister_console() and tty_unregister_driver()
	 * both drain in-flight callers (the former via synchronize_srcu) so no
	 * write path is still touching shared_page before we free it.
	 */
	unregister_console(&bedrock_console);
	if (bedrock_tty_driver) {
		tty_unregister_driver(bedrock_tty_driver);
		tty_driver_kref_put(bedrock_tty_driver);
		tty_port_destroy(&bedrock_tty_port);
		bedrock_tty_driver = NULL;
	}
	if (shared_page) {
		free_page((unsigned long)shared_page);
		shared_page = NULL;
	}
}

module_init(bedrock_console_init);
module_exit(bedrock_console_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bedrock paravirtual batch console + tty");
