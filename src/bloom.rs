use std::hash::{DefaultHasher, Hash, Hasher};

#[derive(Debug, PartialEq, Clone)]
pub struct BloomFilter {
    pub filter: [i32; 10],
}

impl BloomFilter {
    pub fn set_v(&mut self, val: String) {
        let list: Vec<u8> = self.n_hash(val);
        for l in list {
            let i = usize::from(l);
            if self.filter[i] == 0 {
                self.filter[i] = 1
            } else {
                self.filter[i] = 2 }
        }    
    }

    pub fn n_hash(&self, val: String) -> Vec<u8>{
        let hashed = siphash(val);
        let list: Vec<u8> = s_digit(hashed);
        return list
    }

    #[allow(dead_code)]
    pub fn check_v(self, val: String) -> bool {
        let list: Vec<u8> = self.n_hash(val);
        let mut c_bf = BloomFilter { filter: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]};
        for l in list {
            let i = usize::from(l);
            if c_bf.filter[i] == 0 {
                c_bf.filter[i] = 1
            } else {
                c_bf.filter[i] = 2 }
        }
        return self == c_bf
    }
}

fn siphash(s: String) -> u64 {
    let mut siphash = DefaultHasher::new();
    s.hash(&mut siphash);
    return siphash.finish()
}

fn s_digit(n: u64) -> Vec<u8> {
    n.to_string()
        .chars()
        .into_iter()
        .map(|char| char.to_digit(10).unwrap() as u8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloomfilter() {
        let mut bf = BloomFilter { filter: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]};
        bf.set_v("hello world".to_string());
        let expected = [2, 2, 0, 1, 2, 1, 1, 2, 2, 2];
        assert_eq!(expected, bf.filter);

        assert_eq!(bf.clone().check_v("hello world".to_string()), true);
        assert_eq!(bf.clone().check_v("hello world!".to_string()), false);        
    }

    #[test]
    fn test_i32_to_string() {
        let mut bf = BloomFilter { filter: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]};
        bf.set_v("hello world".to_string());
        let mut bloom_str = String::new();
        for i in bf.filter {
            bloom_str = format!("{}{}", bloom_str, i);
        }
        let expected = "2201211222".to_string();
        assert_eq!(bloom_str, expected);
    }

    #[test]
    fn test_string_to_bloomfilter() {
        let str = "2201211222".to_string();
        let mut filter:[i32;10] = [0,0,0,0,0,0,0,0,0,0];
        for (i,c) in str.chars().enumerate() {
            filter[i] = (c.to_string()).parse::<i32>().unwrap();
        }
        let expected = [2, 2, 0, 1, 2, 1, 1, 2, 2, 2];
        assert_eq!(filter, expected);

        let mut bf = BloomFilter { filter: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]};
        bf.set_v("hello world".to_string());
        assert_eq!(filter, bf.filter);

    }

}