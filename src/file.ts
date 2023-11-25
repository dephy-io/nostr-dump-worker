export async function pinjson(jwt, pinataContent, pinataMetadata) {
    const data = JSON.stringify({
        pinataContent,
        pinataMetadata,
    });

    const res = await fetch("https://api.pinata.cloud/pinning/pinJSONToIPFS", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwt}`
        },
        body: data
    })
    const resData = await res.json()
    return resData.IpfsHash
}