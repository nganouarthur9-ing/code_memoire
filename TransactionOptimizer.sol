// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TransactionOptimizer
 * @notice Contrat d'optimisation : reçoit les recommandations IA et 
 *         enregistre les transactions optimisées on-chain
 */
contract TransactionOptimizer {

    address public owner;

    // ── Structure d'une transaction optimisée ─────────────────
    struct OptimizedTx {
        address sender;
        address receiver;
        uint256 amount;
        uint256 timestamp;
        uint256 estimatedGas;    // gas estimé par l'IA (en gwei)
        uint256 actualGas;       // gas réel consommé
        uint8   routeScore;      // score du chemin choisi (0-100)
        string  optimizationNote;// explication de l'IA
        bool    executed;
    }

    OptimizedTx[] public transactions;
    mapping(address => uint256[]) public txBySender;

    // Paramètres d'optimisation mis à jour par l'IA
    uint256 public recommendedGasPrice; // en gwei, mis à jour par Python
    uint256 public networkLoad;         // 0-100 : charge réseau actuelle
    uint256 public lastUpdated;

    // ── Événements ────────────────────────────────────────────
    event TransactionOptimized(
        uint256 indexed txId,
        address indexed sender,
        address indexed receiver,
        uint256 amount,
        uint256 estimatedGas,
        uint8   routeScore
    );
    event GasPriceUpdated(uint256 newPrice, uint256 networkLoad);

    modifier onlyOwner() {
        require(msg.sender == owner, "TO: Not owner");
        _;
    }

    constructor() {
        owner               = msg.sender;
        recommendedGasPrice = 20; // 20 gwei par défaut
        networkLoad         = 50; // 50% charge par défaut
    }

    /**
     * @notice Enregistrer une transaction avec les paramètres optimisés par l'IA
     * @dev Python calcule estimatedGas et routeScore, les envoie ici
     */
    function recordOptimizedTransaction(
        address receiver,
        uint256 amount,
        uint256 estimatedGas,
        uint8   routeScore,
        string  calldata optimizationNote
    ) external returns (uint256 txId) {
        require(receiver != address(0), "TO: Invalid receiver");
        require(amount > 0,             "TO: Amount must be > 0");
        require(routeScore <= 100,      "TO: Invalid route score");

        txId = transactions.length;

        transactions.push(OptimizedTx({
            sender           : msg.sender,
            receiver         : receiver,
            amount           : amount,
            timestamp        : block.timestamp,
            estimatedGas     : estimatedGas,
            actualGas        : 0,      // rempli après exécution
            routeScore       : routeScore,
            optimizationNote : optimizationNote,
            executed         : true
        }));

        txBySender[msg.sender].push(txId);

        emit TransactionOptimized(
            txId, msg.sender, receiver, amount, estimatedGas, routeScore
        );
    }

    /**
     * @notice L'IA Python met à jour le prix de gas recommandé
     * @dev Appelé régulièrement par le backend selon les conditions réseau
     */
    function updateGasRecommendation(
        uint256 newGasPrice,
        uint256 newNetworkLoad
    ) external onlyOwner {
        require(newGasPrice > 0,       "TO: Invalid gas price");
        require(newNetworkLoad <= 100, "TO: Load must be 0-100");

        recommendedGasPrice = newGasPrice;
        networkLoad         = newNetworkLoad;
        lastUpdated         = block.timestamp;

        emit GasPriceUpdated(newGasPrice, newNetworkLoad);
    }

    /** @notice Récupérer les paramètres d'optimisation actuels */
    function getOptimizationParams()
        external view
        returns (uint256 gasPrice, uint256 load, uint256 updated)
    {
        return (recommendedGasPrice, networkLoad, lastUpdated);
    }

    /** @notice Historique des transactions d'un wallet */
    function getTransactionHistory(address sender)
        external view
        returns (uint256[] memory)
    {
        return txBySender[sender];
    }

    /** @notice Récupérer une transaction par ID */
    function getTransaction(uint256 txId)
        external view
        returns (OptimizedTx memory)
    {
        require(txId < transactions.length, "TO: TX not found");
        return transactions[txId];
    }
}
