use std::collections::HashMap;

pub struct MarkovChain {
    count: HashMap<(i32, i32), i32>,
    total: HashMap<i32, i32>,
}

impl MarkovChain {
    pub fn new() -> MarkovChain {
        MarkovChain {
            count: HashMap::new(),
            total: HashMap::new(),
        }
    }

    pub fn add_sequence(&mut self, from: i32, to: i32) {
        *self.count.entry((from, to)).or_insert(0) += 1;
        *self.total.entry(from).or_insert(0) += 1;
    }

    pub fn transition_probability(&self, from: i32, to: i32) -> f64 {
        if let Some(count) = self.count.get(&(from, to)) {
            *count as f64 / *self.total.get(&from).unwrap_or(&1) as f64
        } else {
            0.0
        }
    }
}
