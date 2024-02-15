import * as crypto from 'crypto'
import { computeVerifier, params } from '../index.js'


describe(`test verifier`, function() {

    it(`Test verifier generate from salt TrinityCore`, function() {
        crypto.randomBytes(32, (err, buf) => {
            if (err) throw err
            computeVerifier(params.trinitycore, buf, `tic`, `tac`)
        })
    })

    it(`Test verifier generate from salt AzerothCore`, function() {
        crypto.randomBytes(32, (err, buf) => {
            if (err) throw err
            computeVerifier(params.trinitycore, buf, `tic`, `tac`)
        })
    })

})