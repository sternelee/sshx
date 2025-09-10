#[cfg(test)]
mod tests {
    use shared::events::{ClientMessage, ServerMessage, TerminalData, TerminalInput, NewShell};
    use shared::Sid;

    fn convert_client_to_server_message(client_msg: ClientMessage) -> ServerMessage {
        match client_msg {
            ClientMessage::Data(terminal_data) => {
                let terminal_input = TerminalInput {
                    id: terminal_data.id,
                    data: terminal_data.data,
                    offset: terminal_data.seq,
                };
                ServerMessage::Input(terminal_input)
            }
            ClientMessage::CreatedShell(new_shell) => {
                ServerMessage::CreateShell(new_shell)
            }
            ClientMessage::ClosedShell { id } => {
                ServerMessage::CloseShell { id }
            }
            ClientMessage::Error { message } => {
                ServerMessage::Error { message }
            }
            ClientMessage::Hello { content: _ } => {
                ServerMessage::Ping { 
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64
                }
            }
            ClientMessage::Pong { timestamp } => {
                ServerMessage::Ping { timestamp }
            }
        }
    }

    #[test]
    fn test_terminal_data_conversion() {
        let terminal_data = TerminalData {
            id: Sid(1),
            data: b"hello world".to_vec(),
            seq: 42,
        };
        let client_msg = ClientMessage::Data(terminal_data);
        let server_msg = convert_client_to_server_message(client_msg);
        
        match server_msg {
            ServerMessage::Input(input) => {
                assert_eq!(input.id, Sid(1));
                assert_eq!(input.data, b"hello world");
                assert_eq!(input.offset, 42);
            }
            _ => panic!("Expected ServerMessage::Input"),
        }
    }

    #[test]
    fn test_created_shell_conversion() {
        let new_shell = NewShell {
            id: Sid(2),
            x: 100,
            y: 200,
        };
        let client_msg = ClientMessage::CreatedShell(new_shell.clone());
        let server_msg = convert_client_to_server_message(client_msg);
        
        match server_msg {
            ServerMessage::CreateShell(shell) => {
                assert_eq!(shell.id, Sid(2));
                assert_eq!(shell.x, 100);
                assert_eq!(shell.y, 200);
            }
            _ => panic!("Expected ServerMessage::CreateShell"),
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        // Test that the converted message can be serialized and deserialized
        let terminal_data = TerminalData {
            id: Sid(1),
            data: b"test data".to_vec(),
            seq: 123,
        };
        let client_msg = ClientMessage::Data(terminal_data);
        let server_msg = convert_client_to_server_message(client_msg);
        
        // Serialize to JSON
        let json = serde_json::to_vec(&server_msg).expect("Failed to serialize ServerMessage");
        
        // Deserialize back
        let deserialized: ServerMessage = serde_json::from_slice(&json).expect("Failed to deserialize ServerMessage");
        
        // Verify the content
        match deserialized {
            ServerMessage::Input(input) => {
                assert_eq!(input.id, Sid(1));
                assert_eq!(input.data, b"test data");
                assert_eq!(input.offset, 123);
            }
            _ => panic!("Expected ServerMessage::Input"),
        }
    }
}