// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FintechToken (FTK)
 * @author Stagiaire GTA
 * @notice Token utilitaire ERC-20 pour l'écosystème fintech
 * @dev Intègre : burn automatique, pause d'urgence, rôles admin
 */
contract FintechToken {

    // ── Métadonnées du token ──────────────────────────────────
    string  public name     = "FintechToken";
    string  public symbol   = "FTK";
    uint8   public decimals = 18;
    uint256 public totalSupply;

    // ── Stockage ──────────────────────────────────────────────
    address public owner;
    bool    public paused = false;

    // Taux de burn : 1% de chaque transaction brûlé automatiquement
    uint256 public burnRate = 100; // 100 = 1% (base 10000)

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklisted; // adresses frauduleuses bloquées

    // ── Événements (logs on-chain lisibles par Python) ────────
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event Blacklisted(address indexed account, bool status);
    event Paused(bool status);
    event FraudFlagged(address indexed suspect, uint256 amount, string reason);

    // ── Modificateurs ─────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "FTK: Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "FTK: Contract paused");
        _;
    }

    modifier notBlacklisted(address account) {
        require(!blacklisted[account], "FTK: Address blacklisted (fraud suspected)");
        _;
    }

    // ── Constructeur ──────────────────────────────────────────
    constructor(uint256 initialSupply) {
        owner = msg.sender;
        // Mint initial : 1 000 000 FTK vers le déployeur
        _mint(msg.sender, initialSupply * 10 ** decimals);
    }

    // ── Fonctions ERC-20 standard ─────────────────────────────

    /**
     * @notice Transférer des FTK avec burn automatique de 1%
     * @dev Le destinataire reçoit 99% du montant, 1% est brûlé
     */
    function transfer(address to, uint256 amount)
        external
        whenNotPaused
        notBlacklisted(msg.sender)
        notBlacklisted(to)
        returns (bool)
    {
        require(to != address(0), "FTK: Transfer to zero address");
        require(balanceOf[msg.sender] >= amount, "FTK: Insufficient balance");

        uint256 burnAmount    = (amount * burnRate) / 10000; // 1%
        uint256 transferAmount = amount - burnAmount;        // 99%

        balanceOf[msg.sender] -= amount;
        balanceOf[to]         += transferAmount;
        totalSupply           -= burnAmount; // destruction permanente

        emit Transfer(msg.sender, to, transferAmount);
        emit Burn(msg.sender, burnAmount);
        return true;
    }

    /**
     * @notice Approuver un tiers à dépenser vos tokens (pour les DEX)
     */
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @notice Transfert au nom d'un autre (après approve)
     */
    function transferFrom(address from, address to, uint256 amount)
        external
        whenNotPaused
        notBlacklisted(from)
        notBlacklisted(to)
        returns (bool)
    {
        require(allowance[from][msg.sender] >= amount, "FTK: Allowance exceeded");
        require(balanceOf[from] >= amount, "FTK: Insufficient balance");

        uint256 burnAmount    = (amount * burnRate) / 10000;
        uint256 transferAmount = amount - burnAmount;

        allowance[from][msg.sender] -= amount;
        balanceOf[from]             -= amount;
        balanceOf[to]               += transferAmount;
        totalSupply                 -= burnAmount;

        emit Transfer(from, to, transferAmount);
        emit Burn(from, burnAmount);
        return true;
    }

    // ── Fonctions Admin ───────────────────────────────────────

    /** @notice Créer de nouveaux tokens (admin seulement) */
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /** @notice Brûler des tokens manuellement */
    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "FTK: Insufficient balance");
        balanceOf[msg.sender] -= amount;
        totalSupply           -= amount;
        emit Burn(msg.sender, amount);
    }

    /**
     * @notice Blacklister une adresse frauduleuse (appelé par l'IA via Python)
     * @dev C'est ici que Python connecte l'IA au contrat !
     */
    function setBlacklist(address account, bool status, string calldata reason)
        external
        onlyOwner
    {
        blacklisted[account] = status;
        emit Blacklisted(account, status);
        if (status) {
            emit FraudFlagged(account, 0, reason);
        }
    }

    /** @notice Pause d'urgence (hack détecté) */
    function setPaused(bool status) external onlyOwner {
        paused = status;
        emit Paused(status);
    }

    /** @notice Modifier le taux de burn (en base 10000) */
    function setBurnRate(uint256 newRate) external onlyOwner {
        require(newRate <= 500, "FTK: Max burn 5%");
        burnRate = newRate;
    }

    // ── Fonctions internes ────────────────────────────────────
    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "FTK: Mint to zero address");
        totalSupply    += amount;
        balanceOf[to]  += amount;
        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }
}
