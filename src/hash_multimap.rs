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

    pub fn values(&self) -> HashSet<&V> {
        let mut ret = HashSet::with_capacity(self.inner.len());
        for value_set in self.inner.values() {
            for value in value_set {
                ret.insert(value);
            }
        }
        ret
    }

    pub fn entries<'h>(&'h self) -> Box<dyn Iterator<Item = (&'h K, &'h V)> + 'h> {
        Box::new(
            self.inner
                .iter()
                .flat_map(|(k, v)| v.iter().map(move |v| (k, v))),
        )
    }
}

impl<K: Clone, V: Clone> Clone for HashMultiMap<K, V> {
    fn clone(&self) -> Self {
        HashMultiMap {
            inner: self.inner.clone(),
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
