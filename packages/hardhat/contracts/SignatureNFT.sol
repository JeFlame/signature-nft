// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SignatureNFT is ERC721 {
	// The address that signs the minting requests
	address public immutable signer;

	// A mapping that tracks addresses that have already been used for minting
	mapping(address => bool) public mintedAddress;

	error InvalidSignature();
	error AlreadyMinted();

	// Constructor function that initializes the NFT collection's name, symbol, and signer address
	constructor(address _signer) ERC721("SignatureNFT", "SNFT") {
		signer = _signer;
	}

	// Validates the signature using ECDSA and then mints a new token to the specified address with the given ID
	// _account: 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4
	// _tokenId: 0
	// _signature: 0x390d704d7ab732ce034203599ee93dd5d3cb0d4d1d7c600ac11726659489773d559b12d220f99f41d17651b0c1c6a669d346a397f8541760d6b32a5725378b241c
	function mint(
		address _account,
		uint256 _tokenId,
		bytes memory _signature
	) external {
		bytes32 _msgHash = getMessageHash(_account, _tokenId); // Concatenate the address and token ID to create a message hash
		bytes32 _ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(
			_msgHash
		); // Calculate the Ethereum signed message hash

		// Validate the signature using ECDSA
		if (!verify(_ethSignedMessageHash, _signature)) {
			revert InvalidSignature();
		}
		// Make sure the address hasn't already been used for minting
		if (mintedAddress[_account]) {
			revert AlreadyMinted();
		}

		mintedAddress[_account] = true; // Record that the address has been used for minting
		_mint(_account, _tokenId); // Mint the new token to the specified address
	}

	/*
	 * Concatenates the address and token ID to create a message hash
	 * _account: 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4
	 * _tokenId: 0
	 * The corresponding message hash: 0x1bf2c0ce4546651a1a2feb457b39d891a6b83931cc2454434f39961345ac378c
	 */
	function getMessageHash(
		address _account,
		uint256 _tokenId
	) public pure returns (bytes32) {
		return keccak256(abi.encodePacked(_account, _tokenId));
	}

	// Validates the signature using the ECDSA library
	function verify(
		bytes32 _msgHash,
		bytes memory _signature
	) public view returns (bool) {
		return ECDSA.recover(_msgHash, _signature) == signer;
	}
}
