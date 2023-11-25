import {Hono} from 'hono'
import {SimplePool, Filter} from "nostr-tools"
import {pinjson} from "./file";
import {SignedMessage, RawMessage} from "dephy-proto"
import {base58_to_binary} from "base58-js";
import {hexToBytes} from "ethereum-cryptography/utils";
import {keccak256} from "ethereum-cryptography/keccak";
import {secp256k1} from "ethereum-cryptography/secp256k1";

const app = new Hono()

app.get('/', (c) => {
    return c.text('Hello.')
})

app.post('/test', async (c) => {
//    console.log(c.req.raw.headers)
    console.log(await c.req.text())

    return c.json({a: 1}, {
        status: 400
    })
})

app.get('/dump', async c => {
    let args: DumpArgs
    try {
        args = parseDumpArgs(c.req.query())
    } catch (e) {
        return c.json({
            error: e.toString(),
        }, 400)
    }

    const data = await dump(args)
    return c.json({
        args, data
    })
})

app.get('/dump_and_pin', async c => {
    try {
        const args = parseDumpArgs(c.req.query())
        const d = await dump(args);
        if (d.error) {
            throw new Error(d.error)
        }
        const cid = await pinjson(c.env.PINATA_JWT, {
            args: {
                ...args,
                relays: args.relays.sort()
            },
            events: d.events
        }, {
            keyvalues: {
                ...args,
                relays: args.relays.join(",")
            }
        })
        if (!cid) {
            throw new Error("IPFS pin failed")
        }
        return c.json({
            cid, args, events: d.events
        })
    } catch (e) {
        return c.json({
            error: e.toString(),
        }, 400)
    }
})

export default app

export type DumpArgs =
    {
        from: number
        to: number
        limit?: number
        relays?: string[]
    }

const DEFAULT_RELAY_LIST = ["wss://bobosong.jsjbcz.com"]

function parseDumpArgs(r: Record<string, string>): DumpArgs {
    const from = parseInt(r.from)
    if (!from) {
        throw new Error("Bad `from`")
    }
    const to = parseInt(r.to) || undefined
    if (!to) {
        throw new Error("Bad `to`")
    }
    if (to <= from) {
        throw new Error("Bad `to`")
    }
    const limit = parseInt(r.limit) || 0
    const relays = r.relays?.trim?.().split(",").map(i => i.trim())

    return {
        from,
        to,
        limit,
        relays: relays?.length ? relays : DEFAULT_RELAY_LIST
    }
}

async function dump(args: DumpArgs) {
    const pool = new SimplePool()
    const filters: Filter[] = [{
        kinds: [1111],
        since: args.from,
        until: args.to,
        limit: args.limit || undefined,
        ["#c"]: ["dephy"]
    }] as unknown as Filter[]
    let events
    let error
    try {
        events = await pool.list(args.relays, filters)
    } catch (e) {
        console.error(e, args)
        error = e.toString()
    } finally {
        pool.close(args.relays)
    }
    return {events, error}
}

function verifyEvent(e) {
    const enc = new TextEncoder();

    if (e.kind !== 1111) {
        throw new Error('Bad event kind')
    }
    if (e.tags.filter(i => i[0] === 'c' && i[1] === 'dephy').length === 0) {
        throw new Error('Missing DePHY id tag')
    }

    const eFrom = (e.tags.filter(i => i[0] === 'dephy_from')[0]?.[1] || "").replace("did:dephy:", "")
    const eFromBuf = hexToBytes(eFrom)
    if (eFromBuf.byteLength !== 20) {
        throw new Error('Bad sender in nostr tag')
    }

    const eTo = (e.tags.filter(i => i[0] === 'dephy_to')[0]?.[1] || "").replace("did:dephy:", "")
    const eToBuf = hexToBytes(eTo)
    if (eToBuf.byteLength !== 20) {
        throw new Error('Bad recipient in nostr tag')
    }

    const signedMsg = SignedMessage.decodeBinary(base58_to_binary(e.content))

    if (signedMsg.signature.byteLength !== 65) {
        throw new Error("Bad signature length")
    }

    const nonceBuf = enc.encode(signedMsg.nonce)
    const hashedBuf = function () {
        const buf = new Uint8Array(signedMsg.raw.byteLength + nonceBuf.byteLength)
        buf.set(signedMsg.raw, 0)
        buf.set(nonceBuf, signedMsg.raw.byteLength)
        return buf
    }()
    const currHash = keccak256(hashedBuf)

    if (!compareArray(currHash, signedMsg.hash)) {
        throw new Error("Hash mismatch")
    }

    const rawMsg = RawMessage.decodeBinary(signedMsg.raw)

    if (!compareArray(eFromBuf, rawMsg.fromAddress)) {
        throw new Error('Sender mismatch')
    }
    if (!compareArray(eToBuf, rawMsg.toAddress)) {
        throw new Error('Recipient mismatch')
    }
    if (signedMsg.nonce !== rawMsg.timestamp) {
        throw new Error("Nonce and timestamp mismatch")
    }
    if (Math.abs(e.created_at - parseInt(rawMsg.timestamp)) >= 300) { // 5 minutes tolerance
        throw new Error("Bad create_at value")
    }

    const sign = secp256k1.Signature.fromCompact(signedMsg.signature.slice(0, 64)).addRecoveryBit(signedMsg.signature[64])
    const rPk = sign.recoverPublicKey(keccak256(signedMsg.hash)).toRawBytes(false)
    const rAddr = keccak256(rPk.slice(1)).slice(12)

    if (!compareArray(eFromBuf, rAddr)) {
        throw new Error('Bad singnature')
    }

    return e
}

function compareArray(a, b) {
    return a.length === b.length && a.every((value, index) => value === b[index])
}
