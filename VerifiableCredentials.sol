// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "./ECDSA.sol";

contract VCregistry is ECDSA{

    struct VCMetadata {
        address issuer;
        bytes32 subject;
        uint256 issuedDate;
        Signature signatures;
        bool status;
    }

    struct Signature {
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

 mapping(bytes32 => mapping(address => VCMetadata)) public credential;

function registerCredential(address _issuer, bytes32 _subjectdid, bytes32 _certificateHash, uint256 _issuedDate, bytes calldata _signature) public  returns (bool) {
        credential[_certificateHash][_issuer].issuer=_issuer;
        credential[_certificateHash][_issuer].subject=_subjectdid;
        credential[_certificateHash][_issuer].issuedDate=_issuedDate;
        credential[_certificateHash][_issuer].status=true;
        //emit CredentialRegistered(_issuerdid, _subjectdid, _certificateHash,_issuedDate);
        return true;
    }

function registerSignature(bytes32 _certificateHash, address issuer, bytes calldata _signature) public  returns (bool){
        bytes memory signature = _signature;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        Signature memory _newSignature = Signature(r, s, v);
        bool signExist = false;
        if (credential[_certificateHash][issuer].signatures.r == _newSignature.r 
        && credential[_certificateHash][issuer].signatures.s == _newSignature.s) {
                signExist = true;
        }


        if (signExist) {
            return false;
        } else {
           credential[_certificateHash][issuer]=_newSignature;
            //emit SignatureRegistered(credential.issuer, signExist, _newSignature);
            return true;
        }
    }

function revokeCredential(bytes32 _certificateHash) public  returns (bool) {
        require(credential[_certificateHash][msg.sender].status, "Credential is already revoked");
        credential[_certificateHash][msg.sender].status = false;
        //emit CredentialRevoked(_credentialHash, msg.sender, block.timestamp);
        return true;
    }

function status(bytes32 _certificateHash,address issuer) public  view returns (bool){
        return credential[_certificateHash][issuer].status;
    }

bytes32 constant internal VC_TYPEHASH = keccak256(
        "VCMetadata(address issuer,bytes32 subject,uint256 issuedDate)"
    );

function verifyCredential(VCMetadata memory vc, uint8 v, bytes32 r, bytes32 s) public view returns (bool, bool, bool) {
        bytes32 digest = hashvc(vc);
        bool exists= exist(digest,vc.issuer);
        bool verifystatus=status(digest,vc.issuer);
        bool verifyissuer=verifyIssuer(vc.issuer,ecrecover(digest, v, r, s));
        return (exists, verifystatus,verifyissuer);
    }

function verifySigner(VCMetadata memory vc, bytes calldata _signature) public view returns (bool){
        bytes32 digest = hashvc(vc);
        address signer = recover(digest,_signature);
        return isSigner(digest, vc.issuer, _signature);
    }


function hashvc(VCMetadata memory vc) public pure returns (bytes32) {
 //       hashed= keccak256(
  //              abi.encode(VC_TYPEHASH,
 //               vc.issuer,
  //              vc.subject,
 //               vc.issuedDate,
    //    ));
   //     return hashed;
}

function exist(bytes32 _certificateHash, address issuer) public view returns (bool){
        if (credential[_certificateHash][issuer].issuer == issuer) return true;
        else return false;
    }

function verifyIssuer(address issuer, address signer) public  pure returns (bool isValid){
        return (issuer == signer);
    }

 function isSigner(bytes32 _certificateHash, address _issuer, bytes memory _signature) public  view returns (bool){
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        Signature memory _newSignature = Signature(r, s, v);
        bool signExist = false;

        if (credential[_certificateHash][_issuer].signatures.r == _newSignature.r && credential[_certificateHash][_issuer].signatures.s == _newSignature.s) {
                signExist = true;
        }

        return signExist;
    }

}