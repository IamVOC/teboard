

export type ISOTimeStamp = string

export function newISOTimeStamp(): ISOTimeStamp {
    return new Date().toISOString()
}
