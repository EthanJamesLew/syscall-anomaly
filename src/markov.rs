use std::collections::HashMap;

/// `MarkovChain` represents a Markov chain model for system calls.
/// It holds a chain of system calls as keys to another HashMap, 
/// which then maps to the count of the next system call.
pub struct MarkovChain {
    chain: HashMap<(i32, i32), HashMap<i32, i32>>,
    total_counts: HashMap<(i32, i32), i32>,
}

impl MarkovChain {
    /// Constructs a new, empty `MarkovChain`.
    pub fn new() -> Self {
        MarkovChain {
            chain: HashMap::new(),
            total_counts: HashMap::new(),
        }
    }

    /// Adds a sequence of system calls to the Markov chain.
    pub fn add_sequence(&mut self, prev: (i32, i32), next: i32) {
        let count = self.chain.entry(prev).or_insert(HashMap::new()).entry(next).or_insert(0);
        *count += 1;
        
        let total_count = self.total_counts.entry(prev).or_insert(0);
        *total_count += 1;
    }

    /// Returns the transition probability from one system call sequence to another.
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

    /// Inserts a list of system call numbers into the Markov chain.
    pub fn add_syscalls(&mut self, syscall_numbers: &[i32]) {
        let mut last_syscalls: Option<(i32, i32)> = None;

        for &number in syscall_numbers {
            if let Some(last) = last_syscalls {
                self.add_sequence(last, number);
            }

            last_syscalls = if let Some((_last1, last2)) = last_syscalls {
                Some((last2, number))
            } else {
                Some((100, number))  // Use appropriate default value
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markov_chain() {
        let mut chain = MarkovChain::new();

        chain.add_sequence((1, 2), 3);
        assert_eq!(chain.transition_probability((1, 2), 3), 1.0);
        assert_eq!(chain.transition_probability((1, 2), 4), 0.0);

        chain.add_sequence((1, 2), 4);
        assert_eq!(chain.transition_probability((1, 2), 3), 0.5);
        assert_eq!(chain.transition_probability((1, 2), 4), 0.5);

        chain.add_syscalls(&[5, 6, 7, 8]);
        assert_eq!(chain.transition_probability((100, 5), 6), 1.0);
        assert_eq!(chain.transition_probability((5, 6), 7), 1.0);
        assert_eq!(chain.transition_probability((6, 7), 8), 1.0);
    }
}
