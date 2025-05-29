#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::{
        HashMap,
        lpm_trie::{Key, LpmTrie},
    },
    programs::TcContext,
};
use network_types::{
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use strum::EnumCount;

use core::{mem, net::IpAddr};
use firewall_common::{ConfigOpt, RuleStore};

mod limits;

type ID = [u8; 16];

// Note: I wish we could use const values as map names
// but alas! this is not supported yet https://github.com/rust-lang/rust/issues/52393
// As soon as it is: move map names to const in common crate and use that instead of hardcoding

#[map(name = "SOURCE_ID_IPV4")]
static SOURCE_ID_IPV4: HashMap<[u8; 4], ID> = HashMap::<[u8; 4], ID>::with_max_entries(1024, 0);

#[map(name = "RULE_MAP_IPV4")]
static RULE_MAP_IPV4: LpmTrie<[u8; 21], RuleStore> =
    LpmTrie::<[u8; 21], RuleStore>::with_max_entries(
        limits::MAX_NUMBER_OF_RULES,
        BPF_F_NO_PREALLOC,
    );

#[map(name = "SOURCE_ID_IPV6")]
static SOURCE_ID_IPV6: HashMap<[u8; 16], ID> = HashMap::<[u8; 16], ID>::with_max_entries(1024, 0);

#[map(name = "RULE_MAP_IPV6")]
static RULE_MAP_IPV6: LpmTrie<[u8; 33], RuleStore> =
    LpmTrie::<[u8; 33], RuleStore>::with_max_entries(
        limits::MAX_NUMBER_OF_RULES,
        BPF_F_NO_PREALLOC,
    );

// For now this just configs the default action
// However! We can use this eventually to share more runtime configs
#[map(name = "CONFIG")]
static CONFIG: HashMap<ConfigOpt, i32> =
    HashMap::<ConfigOpt, i32>::with_max_entries(ConfigOpt::COUNT as u32, 0);

#[classifier]
pub fn ebpf_firewall(ctx: TcContext) -> i32 {
    match unsafe { try_ebpf_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn version_inner(hd: u8) -> u8 {
    (hd & 0xf0) >> 4
}

/// This is very similar to `network_types::IpHdr` but gives us generic methods to access the underlying packet fields without destructuring
#[derive(Clone, Copy)]
enum IpHdr<'a> {
    V4 { hdr: Ipv4Hdr, ctx: &'a TcContext },
    V6 { hdr: Ipv6Hdr, ctx: &'a TcContext },
}

enum Transport {
    Tcp(TcpHdr),
    Udp(UdpHdr),
}

impl Transport {
    fn sport(&self) -> u16 {
        match self {
            Transport::Tcp(tcp_hdr) => tcp_hdr.source,
            Transport::Udp(udp_hdr) => udp_hdr.source(),
        }
    }

    fn dport(&self) -> u16 {
        match self {
            Transport::Tcp(tcp_hdr) => tcp_hdr.dest,
            Transport::Udp(udp_hdr) => udp_hdr.dest(),
        }
    }
}

impl<'a> IpHdr<'a> {
    fn proto(&self) -> IpProto {
        match self {
            IpHdr::V4 { hdr, .. } => hdr.proto,
            IpHdr::V6 { hdr, .. } => hdr.next_hdr,
        }
    }

    fn hdr_len(&self) -> usize {
        match self {
            IpHdr::V4 { .. } => ETH_HDR_LEN + Ipv4Hdr::LEN,
            IpHdr::V6 { .. } => ETH_HDR_LEN + Ipv6Hdr::LEN,
        }
    }

    fn ctx(&self) -> &TcContext {
        match self {
            IpHdr::V4 { ctx, .. } => ctx,
            IpHdr::V6 { ctx, .. } => ctx,
        }
    }

    fn transport(&self) -> Option<Transport> {
        unsafe {
            match self.proto() {
                IpProto::Tcp => Some(Transport::Tcp(*ptr_at(self.ctx(), self.hdr_len()).ok()?)),
                IpProto::Udp => Some(Transport::Udp(*ptr_at(self.ctx(), self.hdr_len()).ok()?)),
                _ => None,
            }
        }
    }

    fn sport(&self) -> Option<u16> {
        self.transport().map(|t| t.sport())
    }

    fn dport(&self) -> Option<u16> {
        self.transport().map(|t| t.dport())
    }

    fn saddr(&self) -> IpAddr {
        match self {
            IpHdr::V4 { hdr, .. } => hdr.src_addr().into(),
            IpHdr::V6 { hdr, .. } => hdr.src_addr().into(),
        }
    }

    fn daddr(&self) -> IpAddr {
        match self {
            IpHdr::V4 { hdr, .. } => hdr.dst_addr().into(),
            IpHdr::V6 { hdr, .. } => hdr.dst_addr().into(),
        }
    }

    fn class(&self) -> Option<ID> {
        match self {
            IpHdr::V4 { hdr, .. } => unsafe { SOURCE_ID_IPV4.get(&hdr.src_addr).copied() },
            IpHdr::V6 { hdr, .. } => unsafe { SOURCE_ID_IPV6.get(&hdr.src_addr).copied() },
        }
    }

    fn action(&self) -> Option<i32> {
        match self {
            IpHdr::V4 { hdr, .. } => Some(get_action(
                self.class(),
                hdr.dst_addr,
                &RULE_MAP_IPV4,
                self.dport()?,
                self.proto() as u8,
            )),
            IpHdr::V6 { hdr, .. } => Some(get_action(
                self.class(),
                hdr.dst_addr,
                &RULE_MAP_IPV6,
                self.dport()?,
                self.proto() as u8,
            )),
        }
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// TODO: it could be the case that this isn't an IP packet, then this whole thing is UB.
fn packet(ctx: &TcContext) -> Result<IpHdr, ()> {
    unsafe {
        match version_inner(*ptr_at(ctx, ETH_HDR_LEN)?) {
            4 => Ok(IpHdr::V4 {
                hdr: *ptr_at(ctx, ETH_HDR_LEN)?,
                ctx,
            }),
            6 => Ok(IpHdr::V6 {
                hdr: *ptr_at(ctx, ETH_HDR_LEN)?,
                ctx,
            }),
            _ => Err(()),
        }
    }
}

unsafe fn try_ebpf_firewall(ctx: TcContext) -> Result<i32, ()> {
    let packet = packet(&ctx)?;
    let action = packet.action().ok_or(())?;
    aya_log_ebpf::info!(
        &ctx,
        "[{}] saddr = {} daddr = {} sport = {} dport = {} proto = {}",
        action,
        packet.saddr(),
        packet.daddr(),
        packet.sport().unwrap_or_default(),
        packet.dport().unwrap_or_default(),
        packet.proto() as u8
    );
    Ok(action)
}

fn get_action<const N: usize, const M: usize>(
    group: Option<[u8; 16]>,
    address: [u8; N],
    rule_map: &LpmTrie<[u8; M], RuleStore>,
    port: u16,
    proto: u8,
) -> i32 {
    let proto = if port == 0 { IpProto::Tcp as u8 } else { proto };
    let default_action = get_default_action();

    let rule_store = rule_map.get(&Key::new((M * 8) as u32, get_key(group, proto, address)));
    if is_stored(&rule_store, port) {
        return invert_action(default_action);
    }

    if group.is_some() {
        let rule_store = rule_map.get(&Key::new((M * 8) as u32, get_key(None, proto, address)));
        if is_stored(&rule_store, port) {
            return invert_action(default_action);
        }
    }

    default_action
}

fn invert_action(action: i32) -> i32 {
    if action == TC_ACT_OK {
        TC_ACT_SHOT
    } else {
        TC_ACT_OK
    }
}

fn get_default_action() -> i32 {
    *unsafe { CONFIG.get(&ConfigOpt::DefaultAction) }.unwrap_or(&DEFAULT_ACTION)
}

fn is_stored(rule_store: &Option<&RuleStore>, port: u16) -> bool {
    rule_store.map(|store| store.lookup(port)).unwrap_or(false)
}

fn get_key<const N: usize, const M: usize>(
    group: Option<[u8; 16]>,
    proto: u8,
    address: [u8; N],
) -> [u8; M] {
    let group = group.unwrap_or_default();
    let mut res = [0; M];
    let (res_left, res_address) = res.split_at_mut(17);
    let (res_group, res_proto) = res_left.split_at_mut(16);
    res_group.copy_from_slice(&group);
    res_proto[0] = proto;
    res_address.copy_from_slice(&address);
    res
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const DEFAULT_ACTION: i32 = TC_ACT_SHOT;

#[cfg(not(feature = "wireguard"))]
const ETH_HDR_LEN: usize = network_types::eth::EthHdr::LEN;

#[cfg(feature = "wireguard")]
const ETH_HDR_LEN: usize = 0;
