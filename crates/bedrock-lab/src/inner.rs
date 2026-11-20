// SPDX-License-Identifier: GPL-2.0

//! `LabInner`: the genealogy registry shared by every [`Checkpoint`] and
//! [`Branch`]. Checkpoints register as `Weak` so the registry never extends
//! their lifetime; branches register metadata that they remove on drop.

use std::collections::{BTreeMap, HashMap};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, Weak,
};

use crate::branch::BranchId;
use crate::checkpoint::{Checkpoint, CheckpointId, CheckpointInner};
use crate::event::EventSink;
use crate::time::VirtTime;

/// A live branch, so the tree view can show it.
#[derive(Debug, Clone)]
pub(crate) struct BranchMeta {
    pub(crate) id: BranchId,
    pub(crate) origin: crate::checkpoint::CheckpointId,
    pub(crate) current_time: VirtTime,
}

/// Shared lab state; one per tree.
pub(crate) struct LabInner {
    pub(crate) tsc_frequency: u64,
    next_checkpoint_id: AtomicU64,
    next_branch_id: AtomicU64,
    pub(crate) graph: Mutex<LabGraph>,
    pub(crate) live_branches: Mutex<HashMap<BranchId, BranchMeta>>,
    pub(crate) sink: Arc<dyn EventSink>,
    pub(crate) file_store_dir: Option<std::path::PathBuf>,
}

/// The logical checkpoint tree. Rewinds insert nodes here without changing the
/// VM fork hierarchy (`CheckpointInner::_vm_parent`).
#[derive(Default)]
pub(crate) struct LabGraph {
    checkpoints: HashMap<CheckpointId, Weak<CheckpointInner>>,
    parent: HashMap<CheckpointId, CheckpointId>,
    children: HashMap<CheckpointId, BTreeMap<(VirtTime, CheckpointId), CheckpointId>>,
}

impl LabInner {
    pub(crate) fn new(
        tsc_frequency: u64,
        sink: Arc<dyn EventSink>,
        file_store_dir: Option<std::path::PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tsc_frequency,
            next_checkpoint_id: AtomicU64::new(0),
            // BranchId(0) is reserved for pre-ready root boot events.
            next_branch_id: AtomicU64::new(1),
            graph: Mutex::new(LabGraph::default()),
            live_branches: Mutex::new(HashMap::new()),
            sink,
            file_store_dir,
        })
    }

    pub(crate) fn next_checkpoint_id(&self) -> u64 {
        self.next_checkpoint_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn next_branch_id(&self) -> u64 {
        self.next_branch_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl LabGraph {
    pub(crate) fn register_checkpoint(
        &mut self,
        checkpoint: &Arc<CheckpointInner>,
        parent: Option<CheckpointId>,
    ) {
        self.checkpoints
            .insert(checkpoint.id, Arc::downgrade(checkpoint));
        if let Some(parent) = parent {
            self.parent.insert(checkpoint.id, parent);
            self.children
                .entry(parent)
                .or_default()
                .insert((checkpoint.time, checkpoint.id), checkpoint.id);
        }
    }

    pub(crate) fn reparent(&mut self, child: CheckpointId, new_parent: CheckpointId) {
        let Some(child_inner) = self.checkpoint(child) else {
            return;
        };
        if let Some(old_parent) = self.parent.insert(child, new_parent) {
            if let Some(children) = self.children.get_mut(&old_parent) {
                children.remove(&(child_inner.time, child));
            }
        }
        self.children
            .entry(new_parent)
            .or_default()
            .insert((child_inner.time, child), child);
    }

    pub(crate) fn checkpoint(&self, id: CheckpointId) -> Option<Arc<CheckpointInner>> {
        self.checkpoints.get(&id).and_then(|w| w.upgrade())
    }

    pub(crate) fn parent(&self, id: CheckpointId) -> Option<Arc<CheckpointInner>> {
        self.parent
            .get(&id)
            .and_then(|parent| self.checkpoint(*parent))
    }

    pub(crate) fn checkpoints(&self) -> Vec<Checkpoint> {
        let mut checkpoints: Vec<_> = self
            .checkpoints
            .values()
            .filter_map(|w| w.upgrade())
            .map(|inner| Checkpoint { inner })
            .collect();
        checkpoints.sort_by_key(|cp| cp.id());
        checkpoints
    }
}
