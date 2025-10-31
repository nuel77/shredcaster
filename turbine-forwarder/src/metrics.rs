use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use crossterm::{ExecutableCommand, cursor, terminal};
use tokio::time::sleep;

#[derive(Default, Clone)]
pub struct PacketCtr(Arc<AtomicUsize>);

impl PacketCtr {
    pub fn add(&self, packets: usize) {
        self.0.fetch_add(packets, Ordering::SeqCst);
    }

    pub async fn start_print_loop(self) -> anyhow::Result<()> {
        let mut sto = io::stdout();
        while Arc::strong_count(&self.0) > 1 {
            let val = self.0.load(Ordering::SeqCst);
            sto.execute(cursor::MoveToColumn(0))?
                .execute(terminal::Clear(terminal::ClearType::CurrentLine))?;

            print!("Egress Packets: {val}");
            sto.flush()?;

            sleep(Duration::from_millis(300)).await;
        }

        Ok(())
    }
}
