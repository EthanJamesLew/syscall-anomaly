use std::collections::HashMap;

pub struct MarkovChain {
    chain: HashMap<(i32, i32), HashMap<i32, i32>>,
    total_counts: HashMap<(i32, i32), i32>,
}

impl MarkovChain {
    pub fn new() -> Self {
        MarkovChain {
            chain: HashMap::new(),
            total_counts: HashMap::new(),
        }
    }

    pub fn add_sequence(&mut self, prev: (i32, i32), next: i32) {
        let count = self.chain.entry(prev).or_insert(HashMap::new()).entry(next).or_insert(0);
        *count += 1;
        
        let total_count = self.total_counts.entry(prev).or_insert(0);
        *total_count += 1;
    }

    pub fn transition_probability(&self, from: (i32, i32), to: i32) -> f64 {
        if let Some(counts) = self.chain.get(&from) {
            if let Some(count) = counts.get(&to) {
                *count as f64 / *self.total_counts.get(&from).unwrap_or(&1) as f64
            } else {
                0.0
            }
        } else {
            0.0
        }
    }
}
