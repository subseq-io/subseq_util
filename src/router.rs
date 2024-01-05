use anymap::AnyMap;
use tokio::sync::broadcast;

pub const ROUTER_MESSAGE_SIZE: usize = 1024;

pub struct Router {
    map: AnyMap
}

impl Router {
    pub fn new() -> Self {
        Self{map: AnyMap::new()}
    }
    pub fn subscribe<M: Send + Sync + Clone + 'static>(&mut self) -> broadcast::Receiver<M> {
        self.announce().subscribe()
    }
    pub fn announce<M: Send + Sync + Clone + 'static>(&mut self) -> broadcast::Sender<M> {
        self.map.entry::<broadcast::Sender<M>>()
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(ROUTER_MESSAGE_SIZE);
                tx
        }).clone()
    }
}
