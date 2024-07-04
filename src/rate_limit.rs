use std::collections::VecDeque;

use tokio::sync::mpsc;
use tokio::time::{sleep_until, Duration, Instant};

struct QueuedItem<T> {
    /// The item to store in the rate_channel
    value: T,
    /// When the item can be removed from the rate_channel
    expiration: Instant,
}

struct UsedQueueSlot {
    /// When the slot should be available again
    expiration: Instant,
}

pub struct RateLimitedSender<T>
where
    T: Send + Sync,
{
    tx: mpsc::Sender<QueuedItem<T>>,
    duration_per_item: Duration,
}

impl<T> RateLimitedSender<T>
where
    T: Send + Sync,
{
    pub async fn send(&self, value: T) -> Result<(), T> {
        let item = QueuedItem {
            value,
            expiration: Instant::now() + self.duration_per_item,
        };

        self.tx.send(item).await.map_err(|e| e.0.value)
    }
}

pub struct RateLimitedReceiver<T> {
    rx: mpsc::Receiver<QueuedItem<T>>,
    max_size: usize,
    slots: VecDeque<UsedQueueSlot>,
}

impl<T> RateLimitedReceiver<T>
where
    T: Sync + Send,
{
    pub async fn recv(&mut self) -> Option<T> {
        let now = Instant::now();

        let mut sleep_time = None;
        while let Some(front) = self.slots.front() {
            if now >= front.expiration {
                self.slots.pop_front();
            } else {
                if self.slots.len() >= self.max_size {
                    sleep_time = Some(front.expiration);
                }
                break;
            }
        }

        if let Some(time) = sleep_time {
            sleep_until(time).await;
        }

        let QueuedItem { value, expiration } = self.rx.recv().await?;
        self.slots.push_back(UsedQueueSlot { expiration });
        Some(value)
    }
}

/// Can be used to send items up to the maximum rate_per_duration, at which point it will leak new
/// items out the rx side only when below the max rate.
///
/// Due to differing implementations on your provider side you should probably set this to
/// something like RATE = SPEC_MAX_RATE - 1 to be safe.
pub fn rate_limited_channel<T: Send + Sync>(
    rate_per_duration: usize,
    duration: Duration,
) -> (RateLimitedSender<T>, RateLimitedReceiver<T>) {
    let (tx, rx) = mpsc::channel(rate_per_duration);
    let limited_tx = RateLimitedSender {
        tx,
        duration_per_item: duration,
    };
    let limited_rx = RateLimitedReceiver {
        rx,
        max_size: rate_per_duration,
        slots: VecDeque::with_capacity(rate_per_duration),
    };
    (limited_tx, limited_rx)
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::time::{Duration, Instant};

    #[tokio::test]
    async fn test_rate_limited_channel_happy_path() {
        let (tx, mut rx) = rate_limited_channel::<String>(10, Duration::from_secs(1));
        let start = Instant::now();
        let msg = "hello".to_string();
        tx.send(msg.clone()).await.expect("send");
        let response = rx.recv().await.expect("msg");
        let stop = Instant::now();

        // This should basically be instant
        assert!(stop.duration_since(start) < Duration::from_secs(1));
        assert_eq!(response, msg);
    }

    #[tokio::test]
    async fn test_rate_limited_channel_full() {
        let (tx, mut rx) = rate_limited_channel::<String>(10, Duration::from_secs(1));
        let msgs: Vec<_> = (0..11).into_iter().map(|v| format!("hello{}", v)).collect();

        let start = Instant::now();
        // It should take over 1 second for all these messages to be sent
        tokio::spawn(async move {
            for msg in msgs {
                tx.send(msg).await.expect("send");
            }
        });

        let mut idx = 0;
        while let Some(msg) = rx.recv().await {
            assert_eq!(msg, format!("hello{}", idx));
            idx += 1;
        }
        let stop = Instant::now();
        assert!(stop.duration_since(start) > Duration::from_secs(1));
    }
}
