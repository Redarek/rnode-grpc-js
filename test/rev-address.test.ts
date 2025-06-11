/**
 * Unit-tests for the RChain HD-wallet helpers.
 * The tests print every generated / restored value so you can
 * inspect them in the Jest output.
 */

import {
    newRevAddress,
    revAddressFromMnemonic,
    verifyRevAddr,
} from '../src'

describe('RChain HD-wallet flow', () => {
    test('newRevAddress() produces a valid wallet object', () => {
        const acc = newRevAddress()

        // ---- LOG INPUT / OUTPUT -----------------------------------
        console.log('▶️  Generated wallet')
        console.table({
            mnemonic : acc.mnemonic,
            privKey  : acc.privKey,
            pubKey   : acc.pubKey,
            ethAddr  : acc.ethAddr,
            revAddr  : acc.revAddr,
        })
        // -----------------------------------------------------------

        // mnemonic: 12 words
        expect(acc.mnemonic).toBeDefined()
        expect(acc.mnemonic!.trim().split(' ').length).toBe(12)

        // private key: 32 bytes ⇒ 64 hex chars
        expect(acc.privKey).toMatch(/^[0-9a-f]{64}$/)

        // public key: 65 bytes ⇒ 130 hex chars
        expect(acc.pubKey).toMatch(/^[0-9a-f]{130}$/)

        // ETH address: 20 bytes ⇒ 40 hex chars
        expect(acc.ethAddr).toMatch(/^[0-9a-f]{40}$/)

        // REV checksum must validate
        expect(verifyRevAddr(acc.revAddr)).toBe(true)
    })

    test('revAddressFromMnemonic() restores exactly the same keys', () => {
        const generated = newRevAddress()
        const restored  = revAddressFromMnemonic(generated.mnemonic!)

        // ---- LOG INPUT / OUTPUT -----------------------------------
        console.log('▶️  Restoration from mnemonic')
        console.table({
            mnemonic        : generated.mnemonic,
            generatedPriv   : generated.privKey,
            restoredPriv    : restored.privKey,
            generatedRev    : generated.revAddr,
            restoredRev     : restored.revAddr,
        })
        // -----------------------------------------------------------

        expect(restored.privKey).toBe(generated.privKey)
        expect(restored.pubKey ).toBe(generated.pubKey)
        expect(restored.ethAddr).toBe(generated.ethAddr)
        expect(restored.revAddr).toBe(generated.revAddr)
    })

    test('revAddressFromMnemonic() throws on an invalid phrase', () => {
        // ---- LOG INPUT -------------------------------------------
        console.log('▶️  Attempting restore with invalid mnemonic: "foo bar baz"')
        // -----------------------------------------------------------
        expect(() => revAddressFromMnemonic('foo bar baz'))
            .toThrow('Invalid BIP-39 mnemonic')
    })
})
