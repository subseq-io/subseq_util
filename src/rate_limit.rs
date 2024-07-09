use std::collections::VecDeque;

use tokio::sync::mpsc;
use tokio::time::{sleep_until, Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    pub rate_per_window: usize,
    pub window: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitProfile {
    pub max_rate: RateLimit,
    pub burst_rate: Option<RateLimit>,
}

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
    burst_rate: Option<RateLimit>,

    burst_marker: Option<Instant>,
    burst_count: usize,
}

impl<T> RateLimitedReceiver<T>
where
    T: Sync + Send,
{
    fn reset_burst(&mut self, now: Instant) -> Instant {
        self.burst_marker = Some(now);
        self.burst_count = 1;
        now
    }

    async fn is_bursting(
        &mut self,
        now: Instant,
        burst_start: Instant,
        burst_rate: RateLimit,
    ) -> Instant {
        self.burst_count += 1;
        if self.burst_count >= burst_rate.rate_per_window {
            let later = burst_start
                .checked_add(burst_rate.window)
                .expect("window is sane");
            sleep_until(later).await;

            let now = Instant::now();
            self.reset_burst(now)
        } else {
            now
        }
    }

    async fn manage_burst_rate(&mut self, now: Instant) -> Instant {
        if let Some(burst_rate) = self.burst_rate {
            match self.burst_marker {
                Some(marker) => {
                    if now.duration_since(marker) >= burst_rate.window {
                        self.reset_burst(now)
                    } else {
                        self.is_bursting(now, marker, burst_rate).await
                    }
                }
                None => self.reset_burst(now),
            }
        } else {
            now
        }
    }

    pub async fn recv(&mut self) -> Option<T> {
        let now = self.manage_burst_rate(Instant::now()).await;

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
    profile: RateLimitProfile,
) -> (RateLimitedSender<T>, RateLimitedReceiver<T>) {
    let RateLimitProfile {
        max_rate,
        burst_rate,
    } = profile;
    let (tx, rx) = mpsc::channel(max_rate.rate_per_window);
    let limited_tx = RateLimitedSender {
        tx,
        duration_per_item: max_rate.window,
    };
    let limited_rx = RateLimitedReceiver {
        rx,
        max_size: max_rate.rate_per_window,
        slots: VecDeque::with_capacity(max_rate.rate_per_window),
        burst_rate,
        burst_marker: None,
        burst_count: 0,
    };
    (limited_tx, limited_rx)
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::time::{Duration, Instant};

    #[tokio::test]
    async fn test_rate_limited_channel_happy_path() {
        let profile = RateLimitProfile {
            max_rate: RateLimit {
                rate_per_window: 10,
                window: Duration::from_secs(1),
            },
            burst_rate: None,
        };
        let (tx, mut rx) = rate_limited_channel::<String>(profile);
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
    async fn test_rate_limited_channel_bursting() {
        let profile = RateLimitProfile {
            max_rate: RateLimit {
                rate_per_window: 10,
                window: Duration::from_secs(10),
            },
            burst_rate: Some(RateLimit {
                rate_per_window: 1,
                window: Duration::from_secs(1),
            }),
        };
        let (tx, mut rx) = rate_limited_channel::<String>(profile);
        let msgs: Vec<_> = (0..2).into_iter().map(|v| format!("hello{}", v)).collect();
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

    #[tokio::test]
    async fn test_rate_limited_channel_full() {
        let profile = RateLimitProfile {
            max_rate: RateLimit {
                rate_per_window: 10,
                window: Duration::from_secs(1),
            },
            burst_rate: None,
        };
        let (tx, mut rx) = rate_limited_channel::<String>(profile);
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
