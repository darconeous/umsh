#![allow(async_fn_in_trait)]

#![cfg_attr(not(feature = "std"), no_std)]

pub struct RxInfo {
    pub len: usize,
    pub rssi: i16,
    pub snr: i8,
}

pub trait Radio {
    type Error;

    async fn transmit(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    async fn receive(&mut self, buf: &mut [u8]) -> Result<RxInfo, Self::Error>;
    async fn cad(&mut self) -> Result<bool, Self::Error>;
    fn max_frame_size(&self) -> usize;
    fn t_frame_ms(&self) -> u32;
}

pub trait Clock {
    fn now_ms(&self) -> u64;
}

pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);

    fn random_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn random_range(&mut self, bound: u32) -> u32 {
        if bound <= 1 {
            return 0;
        }

        let zone = u32::MAX - (u32::MAX % bound);
        loop {
            let value = self.random_u32();
            if value < zone {
                return value % bound;
            }
        }
    }
}

pub trait CounterStore {
    type Error;

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error>;
    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error>;
    async fn flush(&self) -> Result<(), Self::Error>;
}

pub trait KeyValueStore {
    type Error;

    async fn load(&self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;
    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error>;
}
