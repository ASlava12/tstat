use std::{fs, path::Path};

/// Прочитать MAC выбранного интерфейса (Linux) без обхода всех интерфейсов.
/// Возвращает вектор, т.к. теоретически могут быть алиасы/вейланы и т.п.
pub fn read_local_macs(iface: Option<&str>) -> Option<Vec<[u8; 6]>> {
    let name = iface?;
    if name == "default" {
        // Не знаем имя — лучше вернём None (пакеты пойдут в "undefined")
        return None;
    }

    let p = format!("/sys/class/net/{}/address", name);
    let path = Path::new(&p);
    if !path.exists() {
        return None;
    }

    let txt = fs::read_to_string(path).ok()?;
    let raw = txt.trim();

    parse_mac(raw).map(|m| vec![m])
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

