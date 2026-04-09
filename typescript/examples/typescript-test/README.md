# TypeScript SDK Example

This example exercises the TypeScript SDK against a running consensus service or mock server.

## Run

```bash
npm install
npm test
```

## Sign Behavior

`sign()` is the only signing interface used by this example.
For voting apps, SDK waits internally and returns final signed/failed result:

```ts
const result = await client.sign(message, 'my-key');
if (!result.success) {
  throw new Error(result.error || 'sign failed');
}
console.log('Signature:', result.signature.toString('hex'));
```
