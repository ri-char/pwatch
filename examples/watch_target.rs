fn main() {
    println!("pid: {}", std::process::id());
    let mut counter = 0;
    loop {
        counter += 1;
        println!("ptr: {:p} {}", &counter, counter);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
