Transactions in GunClear Network assume a Plasma Cash structure for the database of the Gunero chain.

This database is a merkle tree of `tokenID` to `transactionHash` key-value pairs.

The `tokenID` is computed from a hash of the `serial number` of the asset,
as well as a randomized but sequential `nonce` representing the number of times
the asset has been on-boarded into the system.

---

Transaction is a Giver and a Receiver.

Giver and Receiver want to convince the network that they are on the public whitelist,
and that then token they wish to transfer is also on that whitelist.

They do not wish to let the network know who they are,
and want to limit the exposure of any linkable information to the network.

---

Giver first computes a zkSNARK to prove to the Receiver that they have the nullifier necessary
to "unlock" the existing `transactionHash` in the database (and thus can complete the transaction),
as well as prove that they have the private key associated with an entry in the
public whitelist of authorized users.
Giver transmits this proof alongside the `nonce` and `serial number` of the asset
to the Receiver.

(NOTE: Unsure if Giver needs to compute zkSNARK of nullifier beyond just convincing the Receiver)

---

Receiver takes this information from the Giver and computes a zkSNARK to prove to the Network that
the `tokenID` reconstructed from the `serial number` and `nonce`
(after visually inspecting the serial number and asset details) is in the public whitelist of assets,
as well as that they themselves hold a private key associated with an entry in the public whitelist
of authorized users.
The Receiver computes their private `nullifier` in this proof,
and keeps it to themselves for later transactions.

(NOTE: Unsure if Receiver has to compute zkSNARK of TokenID,
or if both can do it in the background after scanning each other's QR codes to obtain the
submitted transaction hash separately)

---

Receiver shares these proofs with the Giver, who transmits the new `transactionHash` along
with the `tokenID` and `nullifier` to the Network.
Both Giver and Receiver (who have knowledge of the `tokenID` and new `transactionHash`) wait
for the transaction to be confirmed and finalized (using the finality properties of Plasma Cash).
