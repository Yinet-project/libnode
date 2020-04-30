use crypto::{digest::Digest, ed25519, ripemd160::Ripemd160, sha3::Sha3};
use kv_hal::kv::Storage;
use kv_hal_sled::SledStorage;
use std::convert::TryFrom;
//use sled;

pub struct NodeInfo {
    seed: [u8; 32],
    secret_key: [u8; 64],
    public_key: [u8; 32],
    node_id: [u8; 20],
}

impl NodeInfo {
    pub async fn new(string: &str, key: &[u8]) -> Self {
        let seed = NodeInfo::get_value(string, key).await;
        if let Ok(seed) = seed {
            if let Some(seed) = seed {
                NodeInfo::init_node(&seed)
            } else {
                NodeInfo::rebuild_key()
            }
        } else {
            NodeInfo::rebuild_key()
        }
    }

    //get seed rand sum from kv-hal-sled trait in the get function
    async fn get_value(string: &str, key: &[u8]) -> Result<Option<Vec<u8>>, sled::Error> {
        let stor = SledStorage::new(string);
        stor.get(key).await
    }

    //如果value存在初始化结构体
    fn init_node(seed_s: &[u8]) -> Self {
        //于rebuild_key接口功能类似，不产生随机种子而是根据入参计算秘钥，秘钥-》nodeid
        let seed: [u8; 32] = TryFrom::try_from(seed_s).unwrap();
        let (secret_key, public_key) = ed25519::keypair(&seed);
        //两次hash   let nodeID = ripemd160(sha3(public key));
        //创建一个SHA3-256的对象
        let mut hasher = Sha3::sha3_256();
        //传入公钥
        hasher.input(&public_key);
        let mut hex: Vec<u8> = Vec::new();
        hasher.result(&mut hex);

        let mut ripemd = Ripemd160::new();
        ripemd.input(&hex);
        let mut node_id: [u8; 20] = [0; 20];
        ripemd.result(&mut node_id);

        Self {
            seed,
            secret_key,
            public_key,
            node_id,
        }
    }

    //通过公钥私钥计算出NodeID
    pub fn get_node(&self) -> [u8; 20] {
        //获取nodeid,rebuild_key里面的算法获取
        let mut hasher = Sha3::sha3_256();
        //传入公钥
        hasher.input(&self.public_key);
        let mut hex: Vec<u8> = Vec::new();
        hasher.result(&mut hex);

        let mut ripemd = Ripemd160::new();
        ripemd.input(&hex);
        let mut node_id: [u8; 20] = [0; 20];
        ripemd.result(&mut node_id);
        assert_eq!(node_id, self.node_id);
        node_id
    }

    //检查是否存在公钥私钥
    pub fn check_key(&self) -> bool {
        //由get_value获取的私钥计算出公钥与数据结构中存在的公秘钥比较
        let (secret_key, public_key) = ed25519::keypair(&self.seed);
        for (i, _) in secret_key.iter().enumerate() {
            assert_eq!(secret_key[i], self.secret_key[i]);
        }
        assert_eq!(public_key, self.public_key);
        if self.secret_key.len() != 64 && self.public_key.len() != 32 {
            return false;
        }
        true
    }

    //如果value不存在生成新的公私钥
    fn rebuild_key() -> Self {
        let iter: [u8; 32] = [0; 32];
        let mut seed: [u8; 32] = [0; 32];
        for (i, _) in iter.iter().enumerate() {
            seed[i] = rand::random::<u8>();
        }
        let (secret_key, public_key) = ed25519::keypair(&seed);
        //两次hash   let nodeID = ripemd160(sha3(public key));
        //创建一个SHA3-256的对象
        let mut hasher = Sha3::sha3_256();
        //传入公钥
        hasher.input(&public_key);
        let mut hex: Vec<u8> = Vec::new();
        hasher.result(&mut hex);

        let mut ripemd = Ripemd160::new();
        ripemd.input(&hex);
        let mut node_id: [u8; 20] = [0; 20];
        ripemd.result(&mut node_id);

        Self {
            seed,
            secret_key,
            public_key,
            node_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node() {
        let node_inf = NodeInfo::new("test/test.db", b"seed").await;

        let value = node_inf.check_key();
        assert_eq!(value, false || true);

        let node = node_inf.get_node();
        assert_eq!(node, node_inf.node_id);
    }
}
