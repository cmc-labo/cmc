use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
#[derive(strum_macros::Display)]
enum Position {
    Right,
    Left,
    None,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Node {
    left: String,
    right: String,
    parent: String,
    sibling: String,
    position: Position,
    data: String,
    hash: String,
}

fn hash(data: String) -> String {
    let h = Sha256::digest(data.clone());
    hex::encode(h).to_string()
}

fn sha256hash(right_data: String, left_data: String) -> String {
        let s = format!("{}{}", right_data, left_data);
        let h = Sha256::digest(s);
        hex::encode(h).to_string()
}

#[derive(Debug, Clone)]
struct Tree {
    leaves: Vec<Node>,
    layer: Vec<Node>,
    root: String,
}

impl Tree {
    fn build_layer(&mut self,n: usize) -> usize{
        let mut num = n;
        let mut new_layer: Vec<Node> = Vec::new();

        if self.layer.len() % 2 == 1 {
            self.layer.push(self.layer[self.layer.len() - 1].clone());
            self.leaves.push(self.leaves[self.leaves.len() - 1].clone());
        }

        for i in (0..self.layer.len()).step_by(2) {
            let parent_data = sha256hash(self.layer[i].hash.clone(), self.layer[i+1].hash.clone());
            let left = Node {left: "".to_string(), right: "".to_string(), parent: parent_data.clone(), sibling: self.layer[i+1].data.clone(), position: Position::Left, data: self.layer[i].data.clone(), hash:hash(self.layer[i].data.clone())};
            let right = Node {left: "".to_string(), right: "".to_string(), parent: parent_data.clone(), sibling: self.layer[i].data.clone(), position: Position::Right, data: self.layer[i+1].data.clone(), hash:hash(self.layer[i+1].data.clone())};
            let parent = Node {left: self.layer[i].data.clone(), right: self.layer[i+1].data.clone(), parent: "".to_string(), sibling: "".to_string(), position: Position::None, data: parent_data.clone(), hash:hash(parent_data.clone())};
            new_layer.push(parent.clone());
            self.leaves[num] = left.clone();
            self.leaves[num+1] = right.clone();
            
            self.leaves.push(parent.clone());
            num = num + 2;
        }
        self.layer = new_layer;
        return num;
    }

    fn build_tree(&mut self) {
        let mut n = 0;
        while self.layer.len() > 1 {
            n = self.build_layer(n);
        }
        self.root = self.layer[0].data.clone();
    }

    // fn search(&mut self, data: String) -> Node {
    //     let mut target = Node {left: "".to_string(), right: "".to_string(), parent: "".to_string(), sibling: "".to_string(), position: Position::None, data: "".to_string(), hash: "".to_string()};
    //     for node in &self.leaves {
    //         if node.data == data {
    //             target = node.clone();
    //         } 
    //     }
    //     return target
    // }

    // fn get_pass(&mut self, data: String) -> Vec<[String; 2]>{
    //     let mut target = self.search(data.clone());
    //     let mut merkle_pass: Vec<[String; 2]> = Vec::new();
    //     merkle_pass.push([target.hash, "".to_string()]);
    //     while target.parent != "" {
    //         let sibling = target.sibling;
    //         for node in &self.leaves {
    //             if node.data == sibling {
    //                 merkle_pass.push([node.hash.clone(), node.position.to_string()]);
    //             } 
    //         }
    //         target = self.search(target.parent);
    //     }       
    //     return merkle_pass
    // }
}

pub fn merkle_root(v: Vec<String>) -> String {
    let mut t = Tree {leaves: [].to_vec(), layer: [].to_vec(), root: "".to_string()};
    for n in v {
        let s =  Node {left: "".to_string(), right: "".to_string(), parent: "".to_string(), sibling: "".to_string(), position: Position::None, data: n.to_string(), hash: hash(n)};
        t.leaves.push(s.clone());
        t.layer.push(s.clone());
    }
    t.build_tree();
    println!("{:?}", t.leaves);
    t.root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root() {
        let vec1: Vec<String> = vec!["Transaction1".to_string(), "Transaction2".to_string(), "Transaction3".to_string(), "Transaction4".to_string(), "Transaction5".to_string(), "Transaction6".to_string(), "Transaction7".to_string()];
        let result1 = merkle_root(vec1);
        let vec2: Vec<String> = vec!["Transaction2".to_string(), "Transaction1".to_string(), "Transaction3".to_string(), "Transaction4".to_string(), "Transaction5".to_string(), "Transaction6".to_string(), "Transaction7".to_string()];
        let result2 = merkle_root(vec2);
        assert_ne!(result1, result2);
    }

    // #[test]
    // fn test_merkle_pass() {
    //     let mut t = Tree {leaves: [].to_vec(), layer: [].to_vec(), root: "".to_string()};
    //     let vec: Vec<String> = vec!["Transaction1".to_string(), "Transaction2".to_string(), "Transaction3".to_string(), "Transaction4".to_string(), "Transaction5".to_string(), "Transaction6".to_string(), "Transaction7".to_string()];
    //     for n in vec {
    //         let s =  Node {left: "".to_string(), right: "".to_string(), parent: "".to_string(), sibling: "".to_string(), position: Position::None, data: n.to_string(), hash: hash(n)};
    //         t.leaves.push(s.clone());
    //         t.layer.push(s.clone());
    //     }
    //     t.build_tree();
    //     println!("{}", t.root);
    //     let merkle_pass = t.get_pass("Transaction3".to_string());
    // }    

}