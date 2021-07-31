mod address;
mod conf;
mod datalink;
mod interfaces;
mod neighbors;
mod packets;
mod proxy;
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
    Ok(())
}
