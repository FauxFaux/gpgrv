use std::collections::hash_map;
use std::collections::hash_set;
use std::collections::HashMap;
use std::collections::HashSet;

use std::hash::Hash;

pub struct HashMultiMap<K, V> {
    inner: HashMap<K, HashSet<V>>,
}

impl<K: Eq + Hash, V: Eq + Hash> HashMultiMap<K, V> {
    pub fn new() -> Self {
        HashMultiMap {
            inner: HashMap::new(),
        }
    }

    pub fn insert(&mut self, k: K, v: V) -> bool {
        self.inner.entry(k).or_insert_with(HashSet::new).insert(v)
    }

    pub fn entries(&self) -> Entries<K, V> {
        Entries {
            outer_iter: self.inner.iter(),
            inner_iter: None,
        }
    }
}

pub struct Entries<'h, K: 'h, V: 'h> {
    outer_iter: hash_map::Iter<'h, K, HashSet<V>>,
    inner_iter: Option<(&'h K, hash_set::Iter<'h, V>)>,
}

impl<'h, K, V: Eq + Hash> Iterator for Entries<'h, K, V> {
    type Item = (&'h K, &'h V);

    // This looks terrible, I must be being dumb...
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.inner_iter.is_none() {
                self.inner_iter = match self.outer_iter.next() {
                    Some((k, v)) => Some((k, v.iter())),
                    None => return None,
                };
            }

            {
                let &mut (k, ref mut it) = self.inner_iter.as_mut().unwrap();
                if let Some(v) = it.next() {
                    return Some((k, v));
                }
            }

            self.inner_iter = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    #[test]
    fn smoke() {
        let mut map = super::HashMultiMap::new();
        assert!(map.insert(5, 2));
        assert!(map.insert(6, 7));
        assert!(map.insert(6, 8));
        assert!(!map.insert(6, 8));

        assert_eq!(3, map.entries().count());
        assert_eq!(
            vec![(5, 2), (6, 7), (6, 8)]
                .into_iter()
                .collect::<HashSet<(u64, u64)>>(),
            map.entries().map(|(k, v)| (*k, *v)).collect()
        );
    }
}
