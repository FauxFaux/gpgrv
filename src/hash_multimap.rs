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
        self.inner
            .entry(k)
            .or_insert_with(|| HashSet::new())
            .insert(v)
    }

    pub fn entries(&self) -> Entries<K, V> {
        Entries {
            inner: self,
            top_iter: self.inner.iter(),
            bot_iter: None,
        }
    }
}

pub struct Entries<'h, K: 'h, V: 'h> {
    inner: &'h HashMultiMap<K, V>,
    top_iter: hash_map::Iter<'h, K, HashSet<V>>,
    bot_iter: Option<(&'h K, hash_set::Iter<'h, V>)>,
}

impl<'h, K, V: Eq + Hash> Iterator for Entries<'h, K, V> {
    type Item = (&'h K, &'h V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.bot_iter.is_none() {
                self.bot_iter = match self.top_iter.next() {
                    Some((k, v)) => Some((k, v.iter())),
                    None => return None,
                };
            }

            if let Some((k, ref mut it)) = self.bot_iter {
                if let Some(v) = it.next() {
                    return Some((k, v));
                }
            }

            self.bot_iter = None;
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
        assert_eq!(vec![(5, 2), (6, 7), (6, 8)].into_iter().collect::<HashSet<(u64, u64)>>(),
                   map.entries().map(|(k, v)| (*k, *v)).collect());
    }
}