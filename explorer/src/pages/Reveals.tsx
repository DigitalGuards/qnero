import type { ReactNode } from 'react';

import { useChain } from '../app/chainContext';
import { formatCount, REFERENCE_CIPHERTEXT_BYTES } from '../lib/units';
import { Notice, Panel } from '../components/ui';

/**
 * What an observer learns, and what stays hidden.
 *
 * Taken from `docs/CIRCUIT.md` section 10 and `docs/WALLET.md`. It is linked
 * from the rail on every page because a reader deciding what this chain is has
 * to be able to find it without reading the circuit.
 */
export function Reveals(): ReactNode {
  const { bundle } = useChain();
  const window = bundle?.context.api.consts['shielded']?.['blockHashWindow']?.toString() ?? '256';

  return (
    <>
      <header className="page__head">
        <h1>What this chain reveals</h1>
        <p className="page__lede">
          Qnero is private by default: every unit of value created after genesis is a note, and no
          transparent transfer between accounts is dispatchable. That still leaves a public record,
          and this page is what is in it.
        </p>
      </header>

      <Panel title="What an observer learns from one block">
        <h3>The block itself</h3>
        <p>
          Its height and hash, its parent, the state and extrinsic roots, and the commitment tree
          root as of that block. The proof of work: the difficulty it was mined against, the seal
          carrying the nonce, and the RandomX seed height, which every client computes from the
          height itself.
        </p>
        <p>
          An author label. It is the 32-byte pre-runtime payload{' '}
          <span className="mono">H(cvk, parent_hash)</span>, so it changes every block. Two blocks
          from one miner carry unrelated labels, and a top-miners table would need a stable identity
          that does not exist.
        </p>

        <h3>Emission</h3>
        <p>
          Every block mints one coinbase note and publishes its value, its leaf index and the
          block it belongs to. Total emission is therefore auditable block by block. What the value
          does not come with is a recipient: the note&rsquo;s inner hash is published in the clear
          and only the holder of the matching coinbase viewing key can recognise it.
        </p>

        <h3>Settlements</h3>
        <p>
          Each accepted submission publishes how many circuit segments it carried, how many leaf
          slots actually settled, and the fee those slots paid. Each settled slot publishes the two
          nullifiers it spent, the two commitments it appended, both leaf indices and both
          ciphertexts.
        </p>
        <p>
          That is the strongest linkage the system has. A payment and its change are publicly a
          pair, at consecutive leaf indices, publicly tied to the two nullifiers spent alongside
          them. Which of the two is the change is hidden only because the wallet draws the
          payment&rsquo;s output slot at random per spend, so this site renders the pair unordered
          and never labels one of them.
        </p>

        <h3>Entries</h3>
        <p>
          A shield is the one linkable event in the system, and it is linkable by construction: it
          burns transparent balance, so the payer&rsquo;s account, the exact amount and the leaf
          index are on chain together. What is not linked is anything after it. The commitment a
          shield publishes is the last time that value has a name.
        </p>

        <h3>Refused calls</h3>
        <p>
          The runtime&rsquo;s call filter is checked at dispatch, so a transparent transfer is a
          valid extrinsic: it enters a block, pays its fee, and then fails. Its arguments stay in
          the block body forever, so one mistaken attempt publishes exactly the sender, recipient
          and amount the policy exists to deny. This site names the call and leaves the arguments
          where the chain put them.
        </p>

        <h3>Totals</h3>
        <p>
          The pool value, the number of entries ever made, every leaf commitment, the tree depth and
          root, the whole settled nullifier set, and every transparent account balance. A vesting
          payout names its beneficiary and amount; a burn names the account it left from.
        </p>
      </Panel>

      <Panel title="What stays hidden">
        <h3>Recipients</h3>
        <p>
          A note is a hash over a public key, a nonce and a randomiser, and the chain only ever
          hashes it. Nothing on chain opens one, so no note names a recipient and no commitment on
          this site is ever an address.
        </p>

        <h3>Amounts</h3>
        <p>
          Note values live inside the commitment and are never published, for every note a
          settlement creates. Two exceptions are structural and both are above: a shield publishes
          its value because it burns transparent balance, and a coinbase publishes its value because
          the chain has to hash it into a commitment over an inner it cannot open. So an observer
          can total emission and total entries, and can total nothing about the notes in between.
        </p>

        <h3>Which note a nullifier spends</h3>
        <p>
          The settled set holds presence only, keyed by the nullifier. A nullifier is a Poseidon2
          output with no published relation to any leaf index. Membership proves some note was
          spent and says nothing about which. There is no on-chain join from a nullifier to a leaf,
          and this site does not invent one.
        </p>

        <h3>The miner&rsquo;s wallet</h3>
        <p>
          No event and no storage item names a block&rsquo;s author. The mining-rewards pallet omits
          it deliberately, and the header&rsquo;s label rotates every block, so the coinbase notes
          one operator produced cannot be grouped into an income stream by anyone without that
          operator&rsquo;s coinbase viewing key.
        </p>
      </Panel>

      <Notice>
        <p>
          Two known leaks are real and are not fixed by an explorer. The gap between a spend&rsquo;s
          anchor block and the block it settles in is a per-wallet marker that tracks the
          prover&rsquo;s speed, and both numbers are public. A note ciphertext of any size other
          than {formatCount(REFERENCE_CIPHERTEXT_BYTES)} bytes was written by something other than
          the reference wallet and is itself a fingerprint.
        </p>
        <p>
          This site shows a ciphertext size where it matters and marks a non-reference one, and it
          makes neither of them a sortable column. Surfacing either as one would turn a documented
          open issue into a deanonymisation tool.
        </p>
      </Notice>

      <Panel title="What this site does not ask the node">
        <p>
          It never calls the Merkle-proof endpoint. Every such call names one specific leaf to
          whoever runs the node, which is the correlation a wallet&rsquo;s local tree rebuild exists
          to avoid, and an explorer making that call for a viewer would hand the node a per-viewer
          leaf-interest log. It reads leaves and the root as public ranges.
        </p>
        <p>
          A settlement may anchor at any canonical block in the {formatCount(Number(window))} before
          the one it lands in. The exact anchor is a public input inside the proof, which this site
          does not open.
        </p>
        <p>
          There is no analytics of any kind here, and no request leaves the page except to the
          configured node.
        </p>
      </Panel>
    </>
  );
}
