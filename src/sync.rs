use std::{
    cell::{RefCell, RefMut},
    ops::DerefMut,
    sync::{Mutex, MutexGuard},
};

use crate::client::ConnectionInner;

pub trait Access {
    type Guard<'g>: DerefMut<Target = ConnectionInner>
    where
        Self: 'g;
    fn lock_mut(&self) -> Self::Guard<'_>;
    fn new(t: ConnectionInner) -> Self;
}
pub type ConnectionMutex = Mutex<ConnectionInner>;
impl Access for Mutex<ConnectionInner> {
    type Guard<'g>
        = MutexGuard<'g, ConnectionInner>
    where
        Self: 'g;
    fn lock_mut(&self) -> Self::Guard<'_> {
        self.lock().unwrap()
    }
    fn new(t: ConnectionInner) -> Self {
        Self::new(t)
    }
}
pub type ConnectionRefCell = RefCell<ConnectionInner>;
impl Access for RefCell<ConnectionInner> {
    type Guard<'g>
        = RefMut<'g, ConnectionInner>
    where
        Self: 'g;
    fn lock_mut(&self) -> Self::Guard<'_> {
        self.borrow_mut()
    }
    fn new(t: ConnectionInner) -> Self {
        Self::new(t)
    }
}
