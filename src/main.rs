mod address;
mod conf;
mod datalink;
mod interfaces;
mod neighbors;
mod packets;
mod nd_proxy;
mod ns_monitor;
mod routing;

use argparse::{ArgumentParser, Store};

#[tokio::main]
async fn main() -> Result<(), ()> {
    pretty_env_logger::init();

    let mut config_filename = String::from("./ndproxy.toml");
    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("proxies your neighbor discovery messages.");
        ap.refer(&mut config_filename).add_option(
            &["-c", "--conf"],
            Store,
            "The location of your config file. Default: ./npproxy.toml",
        );
        ap.parse_args_or_exit();
    }

    // terminate the program if any thread get panicked
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_panic(info);
        std::process::exit(1);
    }));

    let myconf = conf::parse_config(&config_filename);
    let mut fut2 = Vec::new();
    //
    let mut pp = std::collections::HashMap::new();
    //
    let (iface1, iface2) = interfaces::get_ifaces_defined_by_config(&myconf[0]);
    for conf in myconf.into_iter() {
        let mut test = nd_proxy::NDProxier::new(conf).unwrap();
        pp.insert(*test.get_proxied_prefix(), test.mpsc_sender_mut().take().unwrap());
        fut2.push(test.run());
    };

    // select
    use futures::future::join_all;
    use futures::{
        future::FutureExt, // for `.boxed()`
        pin_mut,
        select,
        join
    };
    use tokio::task::spawn_blocking;
    let mut fut = Vec::new();
    for (u, ifs) in iface1 {
        let test = ns_monitor::NSMonitor::new(routing::construst_route_table(pp.clone()), ifs).unwrap();
        fut.push(spawn_blocking(move || { test.run() } ).boxed());
    }
    drop(pp);
    join!(join_all(fut), join_all(fut2));
    Ok(())
}
