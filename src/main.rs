mod address;
mod conf;
mod interfaces;
mod neighors;
mod packets;
mod proxy;

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
            "The location of your config file. Default: ./noproxy.toml",
        );
        ap.parse_args_or_exit();
    }

    let myconf = conf::parse_config(&config_filename);
    // TODO: support multiple sections
    proxy::spawn_monitors_and_forwarders(myconf);
    Ok(())
}

/*
        let (mpsc_tx, mpsc_rx) = channel();

        for (_id, iface) in self.proxied_ifaces.iter() {
            //
            let id = _id.clone();
            let tx = mpsc_tx.clone();
            let iface = iface.clone();
            let pfx = *self.config.get_proxied_pfx();
            //
            let _handle = thread::Builder::new()
                .name(format!(
                    "[{}] NS Listener: {}",
                    self.config.get_name(),
                    iface.get_name()
                ))
                .spawn(move || monitor_NS(iface, id, pfx, tx));
        }
*/
