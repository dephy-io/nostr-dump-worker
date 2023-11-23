import {Hono} from 'hono'
import {SimplePool, Filter} from "nostr-tools";

const app = new Hono()

app.get('/', (c) => {
    return c.text('Hello.')
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