use std::collections::{HashMap, VecDeque};

pub struct NetworkGraph {
    edges: HashMap<String, Vec<String>>, // String is id
}

impl NetworkGraph {
    pub fn new(edges: HashMap<String, Vec<String>>) -> Self {
        Self { edges }
    }

    pub fn optimal_diameter(n: usize, k: usize) -> usize {
        let n = n as f64;
        let k = k as f64;
        (n.ln() / (k - 1.).ln()).ceil() as _
    }

    pub fn find_network_diameter(&self) -> (u32, Vec<u32>) {
        longest_path(&self.edges)
    }
}

fn distance_to_each_other_node(
    node: &str,
    graph: &HashMap<String, Vec<String>>,
) -> HashMap<String, i32> {
    let mut distance = HashMap::new();
    let mut queue = VecDeque::new();
    queue.push_back(node);
    distance.insert(node.to_string(), 0);
    while !queue.is_empty() {
        let current_node = queue.pop_front().unwrap().to_string();
        let current_distance = *distance.get(&current_node).unwrap();
        for next_node in graph.get(&current_node).unwrap() {
            if !distance.contains_key(next_node) {
                distance.insert(next_node.to_string(), current_distance + 1);
                queue.push_back(next_node);
            }
        }
    }
    if distance.len() != graph.len() {
        println!("Distance at {} is in-complete {}", node, distance.len());
        if distance.len() == 1 {
            println!("1 at {}", node);
        }
    }
    distance
}

fn longest_path(graph: &HashMap<String, Vec<String>>) -> (u32, Vec<u32>) {
    let mut distances = Vec::new();
    let mut max_distance = 0;
    for (node, _) in graph.iter() {
        let distance = distance_to_each_other_node(node, graph);
        for (_, d) in distance.iter() {
            if *d > max_distance {
                max_distance = *d;
            }
        }
        distances.push(max_distance as u32);
    }
    (max_distance as u32, distances)
}
