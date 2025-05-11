use sha1::Digest;
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

const SHA1_HEX_LEN: usize = 40;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("usage: ./sha1_cracker <wordlist.txt> <sha1_hash>");
        return Ok(());
    }

    let hash = args[2].trim();
    if hash.len() != SHA1_HEX_LEN {
        return Err("sha1 hash is not valid".into());
    }

    let wordlist = File::open(&args[1].trim())?;
    let reader = BufReader::new(&wordlist);

    for line in reader.lines() {
        let line = line?;
        if hash == &hex::encode(sha1::Sha1::digest(line.trim().as_bytes())) {
            println!("Password found: {}", &line.trim());
            return Ok(());
        }
    }
    println!("Password not found in wordlist :(");
    Ok(())
}
