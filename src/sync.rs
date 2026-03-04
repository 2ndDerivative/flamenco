use std::{
    cell::{RefCell, RefMut},
    ops::DerefMut,
    sync::{Mutex, MutexGuard},
};

pub trait Access<T> {
    type Guard<'g>: DerefMut<Target = T>
    where
        Self: 'g;
    fn lock_mut(&self) -> Self::Guard<'_>;
    fn new(t: T) -> Self;
}
impl<T> Access<T> for Mutex<T> {
    type Guard<'g>
        = MutexGuard<'g, T>
    where
        Self: 'g;
    fn lock_mut(&self) -> Self::Guard<'_> {
        self.lock().unwrap()
    }
    fn new(t: T) -> Self {
        Self::new(t)
    }
}
impl<T> Access<T> for RefCell<T> {
    type Guard<'g>
        = RefMut<'g, T>
    where
        Self: 'g;
    fn lock_mut(&self) -> Self::Guard<'_> {
        self.borrow_mut()
    }
    fn new(t: T) -> Self {
        Self::new(t)
    }
}
