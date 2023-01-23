// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "erc721a/contracts/ERC721A.sol";
import "operator-filter-registry/src/DefaultOperatorFilterer.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// $$$$$$$\                                                $$$$$$$\                                $$\           
// $$  __$$\                                               $$  __$$\                               $$ |          
// $$ |  $$ | $$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\        $$ |  $$ | $$$$$$\  $$\   $$\  $$$$$$\  $$ | $$$$$$\  
// $$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\       $$$$$$$  |$$  __$$\ $$ |  $$ | \____$$\ $$ |$$  __$$\ 
// $$ |  $$ |$$$$$$$$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |      $$  __$$< $$ /  $$ |$$ |  $$ | $$$$$$$ |$$ |$$$$$$$$ |
// $$ |  $$ |$$   ____|$$ |  $$ |$$   ____|$$ |  $$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ |$$  __$$ |$$ |$$   ____|
// $$$$$$$  |\$$$$$$$\ \$$$$$$$ |\$$$$$$$\ $$ |  $$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$ |\$$$$$$$ |$$ |\$$$$$$$\ 
// \_______/  \_______| \____$$ | \_______|\__|  \__|      \__|  \__| \______/  \____$$ | \_______|\__| \_______|
//                     $$\   $$ |                                              $$\   $$ |                        
//                     \$$$$$$  |                                              \$$$$$$  |                        
//                      \______/                                                \______/

/**
 * @title Degen Royale: Cash Gun NFT Minting Contract
 * @author @Xirynx
 * @notice 2 Phase NFT mint. 2000 max supply.
 */
contract DegenRoyaleNFT is ERC721A("Degen Royale: Cash Gun", "DGCG"), Ownable, DefaultOperatorFilterer {

	//============================================//
	//                Definitions                 //      
	//============================================//

	using ECDSA for bytes;

	enum Phase{
		NONE,
		WHITELIST,
		PUBLIC
	}

	//============================================//
	//                  Errors                    //   
	//============================================//

	error MaxSupplyExceeded();
	error MaxMintAmountExceeded();
	error AddressNotWhitelisted();
	error InsufficientETH();
	error CallerNotOrigin();
	error IncorrectPhase();
	error InvalidSigner();

	//============================================//
	//              State Variables               //        
	//============================================//

	uint256 public constant MAX_SUPPLY = 2000;
	uint8 public constant MAX_PER_WALLET_WHITELIST = 2;
	uint8 public constant MAX_PER_WALLET_PUBLIC = 2;
	uint256 public mintPrice;
	bytes32 public merkleRoot;
	string internal baseURI;
	address public signer;
	Phase public phase = Phase.NONE;

	//============================================//
	//              Admin Functions               //        
	//============================================//

    /** 
	 * @notice Sets the mint price for all mints
	 * @dev Caller must be contract owner
	 * @param _mintPrice New mint price in wei
	 */
	function setMintPrice(uint256 _mintPrice) public onlyOwner { 
        mintPrice = _mintPrice;
    }

    /** 
	 * @notice Sets the merkle tree root used to verify whitelist mints
	 * @dev Caller must be contract owner
	 * @param _merkleRoot New root of merkle tree for whitelist mints
	 */
	function setMerkleRoot(bytes32 _merkleRoot) public onlyOwner { 
        merkleRoot = _merkleRoot;
    }

    /** 
	 * @notice Sets the new signer wallet used to verify public mints
	 * @dev Caller must be contract owner
	 * @param _signer New root of merkle tree for whitelist mints
	 */
	function setSigner(address _signer) external onlyOwner {
		signer = _signer;
	}

    /** 
	 * @notice Sets the base uri for token metadata
	 * @dev Caller must be contract owner
	 * @param _newURI New base uri for token metadata
	 */
	function setBaseURI(string memory _newURI) external onlyOwner {
		baseURI = _newURI;
	}

    /** 
	 * @notice Starts the whitelist minting phase
	 * @dev Caller must be contract owner
	 * @param _merkleRoot New root of merkle tree for whitelist mints. Can be alterred at any point using `setMerkleRoot`
	 * @param _mintPrice New mint price in wei for the whitelist mint. Can be alterred at any point using `setMintPrice`
	 */
    function startWhitelistPhase(bytes32 _merkleRoot, uint256 _mintPrice) external onlyOwner { 
        setMintPrice(_mintPrice);
        setMerkleRoot(_merkleRoot);
        phase = Phase.WHITELIST;
    }

    /**
	 * @notice Starts the public minting phase
	 * @dev Caller must be contract owner
	 * @param _mintPrice New mint price in wei for the public mint. Can be alterred using Can be alterred at any point using `setMintPrice`
	 */
    function startPublicPhase(uint256 _mintPrice) external onlyOwner { 
        setMintPrice(_mintPrice);
        phase = Phase.PUBLIC;
    }

    /**
	 * @notice Stops sale entirely. No mints can be made by users other than admins
	 * @dev Caller must be contract owner
	 */
	function stopSale() external onlyOwner { 
        phase = Phase.NONE;
    }

    /**
	 * @notice Withdraws entire ether balance in the contract to the wallet specified
	 * @dev Caller must be contract owner
	 * @param to Address to send ether balance to
	 */
	function withdrawFunds(address to) public onlyOwner {
        uint256 balance = address(this).balance;
        (bool callSuccess, ) = payable(to).call{value: balance}("");
        require(callSuccess, "Call failed");
    }

	//============================================//
	//               Access Control               //        
	//============================================//

	/**
	 * @notice Verifies that an address forms part of the merkle tree with the current `merkleRoot`
	 * @param wallet Address to compute leaf node of merkle tree
	 * @param _merkleProof Bytes array proof to verify `wallet` is part of merkle tree
	 * @return bool True if `wallet` is part of the merkle tree, false otherwise
	 */
	function verifyWhitelist(address wallet, bytes32[] calldata _merkleProof) public view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(wallet));
        return MerkleProof.verify(_merkleProof, merkleRoot, leaf);       
    }

	/**
	 * @notice Verifies that a message was signed by the current `signer` wallet
	 * @param _data Bytes encoded message data
	 * @param _signature Signed message data
	 * @return bool True if `_data` was signed by `signer`, false otherwise
	 */
	function verifySigner(bytes memory _data, bytes memory _signature) public view returns (bool) {
		bytes32 _hash = _data.toEthSignedMessageHash();
		if (ECDSA.recover(_hash, _signature) != signer) return false;
		return true;
	}

	//============================================//
	//              Helper Functions              //        
	//============================================//

	/**
	 * @notice Gets number of tokens minted by `wallet` in total
	 * @param wallet Address of the minter
	 * @return uint256 Number of tokens
	 */
	function numberMinted(address wallet) public view returns (uint256) {
		return _numberMinted(wallet);
	}

	/**
	 * @notice Gets number of tokens minted by `wallet` during a specific phase
	 * @dev Bits [0-31] represent the number minted during the whitelist phase
	 		Bits [31-63] represent the number minted during the public phase
	 * @param wallet Address of the minter
	 * @param _phase The phase of the mint
	 * @return uint32 Number of tokens minted during specified phase, or 0
	 */
	function numberMinted(address wallet, Phase _phase) public view returns (uint32) {
		if (_phase == Phase.WHITELIST) {
			return uint32(_getAux(wallet) & ((1 << 32) - 1)); // Last 32 bits represents number minted during whitelist phase
		}
		if (_phase == Phase.PUBLIC) {
			return uint32(_getAux(wallet) >> 32); // First 32 bits represents number minted during public phase
		}
		return uint32(0);
	}

	//============================================//
	//                Minting Logic               //        
	//============================================//

	/**
	 * @notice Mints `amount` tokens to `to` address
	 * @dev Caller must be contract owner
	 		`amount` must be less than or equal to 30. This avoids excessive first time gas fees for NFT transfers in the ERC721A standard.
	 * 		`amount` cannot cause total supply to go over `MAX_SUPPLY`
	 * @param to Address that will receive the tokens
	 * @param amount Number of tokens to send to `to`
	 */
	function adminMint(address to, uint256 amount) external onlyOwner {
		if (amount + _totalMinted() > MAX_SUPPLY) revert MaxSupplyExceeded();
		if (amount > 30) revert MaxMintAmountExceeded();
		_mint(to, amount);
	}

	/**
	 * @notice Mints `amount` tokens to caller's address
	 * @dev Caller must be an externally owned account
	 * 		`phase` must equal WHITELIST
	 *		Total supply must be less than or equal to `MAX_SUPPLY` after mint
	 *		Caller must not mint more than `MAX_PER_WALLET_WHITELIST` tokens total during the whitelist phase
	 *      Value sent in function call must exceed or equal `mintPrice` multiplied by `amount`
	 *		Caller must be whitelisted
	 * @param _merkleProof Proof that proves caller is part of merkle tree specified by `merkleRoot`
	 * @param amount Amount of tokens to mint
	 */
	function whitelistMint(bytes32[] calldata _merkleProof, uint8 amount) external payable {
		if (tx.origin != msg.sender) revert CallerNotOrigin();
		if (phase != Phase.WHITELIST) revert IncorrectPhase();
		if (_totalMinted() + amount > MAX_SUPPLY) revert MaxSupplyExceeded();
		uint256 numMinted = numberMinted(msg.sender, Phase.WHITELIST) + amount;
		if (numMinted > MAX_PER_WALLET_WHITELIST) revert MaxMintAmountExceeded();
		if (msg.value < mintPrice * amount) revert InsufficientETH();
		if (!verifyWhitelist(msg.sender, _merkleProof)) revert AddressNotWhitelisted();
		uint64 auxData = _getAux(msg.sender);
		_setAux(msg.sender, uint64(auxData & ((1 << 32) - 1) << 32 | numMinted));
		_mint(msg.sender, amount);
	}

	/**
	 * @notice Mints `amount` tokens to caller's address
	 * @dev Caller must be an externally owned account
	 * 		`phase` must equal PUBLIC
	 *		Caller must not mint more than `MAX_PER_WALLET_PUBLIC` tokens total during the public phase
	 *		Total supply must be less than or equal to `MAX_SUPPLY` after mint
	 *      Value sent in function call must exceed or equal `mintPrice` multiplied by `amount`
	 *		Signer should sign caller's address (encoded as bytes) and their current `numberMinted` before they are allowed to mint
	 * @param _signature Signature proving that account is allowed to mint during this phase
	 * @param amount Amount of tokens to mint
	 */
	function publicMint(bytes memory _signature, uint8 amount) external payable {
		if (tx.origin != msg.sender) revert CallerNotOrigin();
		if (phase != Phase.PUBLIC) revert IncorrectPhase();
		uint256 numMinted = numberMinted(msg.sender, Phase.PUBLIC) + amount;
		if (numMinted > MAX_PER_WALLET_PUBLIC) revert MaxMintAmountExceeded();
		if (_totalMinted() + amount > MAX_SUPPLY) revert MaxSupplyExceeded();
		if (msg.value < mintPrice * amount) revert InsufficientETH();
		bytes memory _data = abi.encode(msg.sender, _numberMinted(msg.sender));
		if (!verifySigner(_data, _signature)) revert InvalidSigner();
		uint64 auxData = _getAux(msg.sender);
		_setAux(msg.sender, uint64(auxData & ((1 << 32) - 1) | numMinted << 32));
		_mint(msg.sender, amount);
	}

	//============================================//
	//              ERC721 Overrides              //        
	//============================================//

	/**
	 * @notice Overridden to return variable `baseURI` rather than constant string. Allows for flexibility to alter metadata in the future.
	 * @return string the current value of `baseURI`
	 */
	function _baseURI() internal view override returns (string memory) {
        return baseURI;
    }

	//============================================//
	//         Opensea Registry Overrides         //        
	//============================================//

	function setApprovalForAll(address operator, bool approved) public override onlyAllowedOperatorApproval(operator) {
		super.setApprovalForAll(operator, approved);
	}

	function approve(address operator, uint256 tokenId) public payable override onlyAllowedOperatorApproval(operator) {
		super.approve(operator, tokenId);
	}

	function transferFrom(address from, address to, uint256 tokenId) public payable override onlyAllowedOperator(from) {
		super.transferFrom(from, to, tokenId);
	}

	function safeTransferFrom(address from, address to, uint256 tokenId) public payable override onlyAllowedOperator(from) {
		super.safeTransferFrom(from, to, tokenId);
	}

	function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
		public
		payable
		override
		onlyAllowedOperator(from)
	{
		super.safeTransferFrom(from, to, tokenId, data);
	}
}
