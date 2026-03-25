use super::BLOCK_LAYERS;

#[test]
fn block_layer_list_covers_connect_accept_and_resource_assignment() {
    assert_eq!(
        BLOCK_LAYERS.len(),
        6,
        "expected IPv4/IPv6 layers for connect, recv_accept, and resource_assignment"
    );
}
