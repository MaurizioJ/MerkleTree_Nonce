import process from 'process';
import { createRequire } from 'module';
import {createMerkleTree,CryptoSHALeaves, CryptoSHATree} from './creationMekleTree.js'

const require = createRequire(import.meta.url);
const util = require('util');
const SHA256 = require('crypto-js/sha256')
const SHA512 = require('crypto-js/sha512')
const SHA3 = require('crypto-js/sha3')
const { MerkleTree } = require('merkletreejs')


let crypto;
var config =require('../config.json');

crypto = require('crypto');
export const verifyAttributes = async (VCs, VP)  => {

    // console.log("VP")
    // console.log(VP.vp.pr)
    var listHashedValue =[]
    let listValue= VP.vp.attributes
    const listProof = VP.vp.proof
    var listProofBuff = []

    for(const credential of VCs){


        var credVC = credential.credentialSubject
        // var tree = new MerkleTree(credVC["merkleTree"],SHA256)
        var root = credVC["root"] // recupero il nodo radice
           // listValue= listValue.map(x=>(CryptoSHALeaves(x,listProof.nonceLeaves)))
        for(let i=0; i<listValue.length;i++){
           let obj=  await CryptoSHALeaves(listValue[i],listProof[i].nonceLeaves)
           listProofBuff[i]= MerkleTree.unmarshalProof(listProof[i].listPathNodes) // proof fornita come lista di buffer
            listHashedValue.push(obj.hashedLeaves)
        }

             // console.log("Grandezze lista valori da hashare " + listProof.length)
        for(let i=0;i<listProofBuff.length;i++){ // scorro la lista dei valori che voglio verificare
            // console.log(MerkleTree.bufferToHex(Buffer.from(listProof[i].listPathNodes)))
            // console.log(listProof[i].name)
            // console.log((listProof[i].listPathNodes))

            if(MerkleTree.verify(listProofBuff[i], listHashedValue[i].toString(), root,CryptoSHATree)){

                 // console.log("Il nodo foglia " + listValue[i] + " è stato verificato con SUCCESSO");
            } 
            else {
                console.log("Il nodo foglia " + listValue[i] + " NON è stato verificato con SUCCESSO");
                return;
            } 

        }


    }

return ;
}