# zkred-agent-id

A package for zkred agent identification.

## Installation

```bash
npm install zkred-agent-id
```

## Usage

```typescript
import { createAgentId } from 'zkred-agent-id';

// Create a new agent identifier
const agent = createAgentId('bot', { 
  capabilities: ['text', 'image'],
  version: '1.0.0'
});

console.log(agent);
// Output: { id: 'unique-id', type: 'bot', metadata: { capabilities: ['text', 'image'], version: '1.0.0' } }
```

## API

### createAgentId(type, metadata)

Creates a new agent identifier.

- `type` (string): The type of agent
- `metadata` (object, optional): Additional metadata for the agent

Returns an `AgentIdentifier` object with the following properties:
- `id`: A unique identifier string
- `type`: The agent type
- `metadata`: Optional metadata object

## License

MIT