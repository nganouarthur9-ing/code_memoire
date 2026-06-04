// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FraudRegistry
 * @notice Registre on-chain des fraudes détectées par l'IA Python
 * @dev Python envoie les résultats IA ici → stockés de façon immuable
 */
contract FraudRegistry {

    address public owner;
    address public aiOracle; // adresse du backend Python autorisé à écrire

    // ── Structure d'un rapport de fraude ─────────────────────
    struct FraudReport {
        address  suspect;        // adresse du wallet suspect
        address  victim;         // adresse victime (si connue)
        uint256  amount;         // montant impliqué (en wei)
        uint256  timestamp;      // horodatage blockchain
        uint8    riskScore;      // score IA : 0-100
        string   riskLevel;      // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        string   modelUsed;      // "RandomForest" | "XGBoost"
        bool     blocked;        // transaction bloquée ?
        string   txHash;         // hash de la transaction originale
    }

    // ── Stockage ──────────────────────────────────────────────
    FraudReport[] public reports;
    mapping(address => uint256[]) public reportsByAddress; // index par wallet
    mapping(address => uint256)   public fraudCount;       // nb fraudes par adresse
    mapping(string => bool)       public processedTxHashes; // éviter les doublons

    uint256 public totalReports;
    uint256 public totalBlocked;

    // ── Événements ────────────────────────────────────────────
    event FraudReported(
        uint256 indexed reportId,
        address indexed suspect,
        uint8   riskScore,
        string  riskLevel,
        bool    blocked
    );
    event OracleUpdated(address indexed newOracle);

    // ── Modificateurs ─────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "FR: Not owner");
        _;
    }

    modifier onlyOracle() {
        require(
            msg.sender == aiOracle || msg.sender == owner,
            "FR: Not authorized oracle"
        );
        _;
    }

    // ── Constructeur ──────────────────────────────────────────
    constructor() {
        owner     = msg.sender;
        aiOracle  = msg.sender; // par défaut, l'owner est l'oracle
    }

    // ── Fonction principale : Python envoie les résultats IA ──

    /**
     * @notice Enregistrer un rapport de fraude détecté par l'IA
     * @dev Appelé automatiquement par le backend Python après analyse ML
     * @param suspect Adresse du wallet analysé
     * @param victim  Adresse destinataire (peut être address(0) si inconnue)
     * @param amount  Montant de la transaction suspecte
     * @param riskScore Score de 0 à 100 calculé par le modèle ML
     * @param riskLevel Catégorie textuelle du risque
     * @param modelUsed Nom du modèle ML utilisé
     * @param blocked  L'IA a-t-elle bloqué la transaction ?
     * @param txHash   Hash de référence de la transaction
     */
    function reportFraud(
        address suspect,
        address victim,
        uint256 amount,
        uint8   riskScore,
        string  calldata riskLevel,
        string  calldata modelUsed,
        bool    blocked,
        string  calldata txHash
    ) external onlyOracle {
        require(suspect != address(0),        "FR: Invalid suspect address");
        require(riskScore <= 100,             "FR: Score must be 0-100");
        require(!processedTxHashes[txHash],   "FR: Transaction already processed");

        processedTxHashes[txHash] = true;

        uint256 reportId = reports.length;

        reports.push(FraudReport({
            suspect   : suspect,
            victim    : victim,
            amount    : amount,
            timestamp : block.timestamp,
            riskScore : riskScore,
            riskLevel : riskLevel,
            modelUsed : modelUsed,
            blocked   : blocked,
            txHash    : txHash
        }));

        reportsByAddress[suspect].push(reportId);
        fraudCount[suspect]++;
        totalReports++;
        if (blocked) totalBlocked++;

        emit FraudReported(reportId, suspect, riskScore, riskLevel, blocked);
    }

    // ── Fonctions de lecture (gratuites) ──────────────────────

    /** @notice Récupérer un rapport par son ID */
    function getReport(uint256 reportId)
        external view
        returns (FraudReport memory)
    {
        require(reportId < reports.length, "FR: Report not found");
        return reports[reportId];
    }

    /** @notice Tous les IDs de rapports pour une adresse */
    function getReportsByAddress(address account)
        external view
        returns (uint256[] memory)
    {
        return reportsByAddress[account];
    }

    /** @notice Vérifier si une adresse est un fraudeur récidiviste */
    function isHighRiskAddress(address account)
        external view
        returns (bool, uint256)
    {
        return (fraudCount[account] >= 3, fraudCount[account]);
    }

    /** @notice Statistiques globales du registre */
    function getStats()
        external view
        returns (uint256 total, uint256 blocked, uint256 ratio)
    {
        total   = totalReports;
        blocked = totalBlocked;
        ratio   = total > 0 ? (blocked * 100) / total : 0;
    }

    // ── Admin ─────────────────────────────────────────────────

    /** @notice Changer l'adresse du backend Python autorisé */
    function setOracle(address newOracle) external onlyOwner {
        aiOracle = newOracle;
        emit OracleUpdated(newOracle);
    }
}
