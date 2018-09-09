/**
 * Copyright (c) 2017-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
*/

package com.facebook.research.asynchronousratchetingtree.art;

import com.facebook.research.asynchronousratchetingtree.Utils;
import com.facebook.research.asynchronousratchetingtree.art.message.AuthenticatedMessage;
import com.facebook.research.asynchronousratchetingtree.art.message.SetupMessage;
import com.facebook.research.asynchronousratchetingtree.art.message.UpdateMessage;
import com.facebook.research.asynchronousratchetingtree.art.tree.*;
import com.facebook.research.asynchronousratchetingtree.crypto.Crypto;
import com.facebook.research.asynchronousratchetingtree.crypto.DHKeyPair;
import com.facebook.research.asynchronousratchetingtree.crypto.DHPubKey;

import java.math.BigInteger;
import java.util.*;

public class ART {
  public static AuthenticatedMessage setupGroup(ARTState state, DHPubKey[] peers, Map<Integer, DHPubKey> preKeys) {
    int numPeers = peers.length;

    DHKeyPair selfLeaf = DHKeyPair.generate(false);
    DHKeyPair keyExchangeKeyPair = DHKeyPair.generate(false);

    DHKeyPair[] leaves = new DHKeyPair[numPeers];
    leaves[0] = selfLeaf;

    for (int i = 1; i < numPeers; i++) {  // generate leaf keys for each agent
      leaves[i] = DHKeyPair.fromBytes(
        Crypto.keyExchangeInitiate(
          state.getIdentityKeyPair(),
          peers[i],
          keyExchangeKeyPair,
          preKeys.get(i)
        ),
        false
      );
    }
    SecretNode tree = createTree(leaves);
    state.setIdentities(peers);
    state.setTree(tree);
    
    SetupMessage sm = new SetupMessage(
		peers,
      preKeys,
      keyExchangeKeyPair.getPubKey(),
      tree
    );
    byte[] serialisedSetupMessage = sm.serialise();
    byte[] signature = state.getIdentityKeyPair().sign(serialisedSetupMessage);
    deriveStageKey(state);

    return new AuthenticatedMessage(serialisedSetupMessage, signature);
  }

  public static void processSetupMessage(ARTState state, AuthenticatedMessage signedMessage, int leafNum) {
    SetupMessage message = new SetupMessage(signedMessage.getMessage());
    boolean verified = message.getIdentities()[0].verify(signedMessage.getMessage(), signedMessage.getAuthenticator());
    if (!verified) {
      Utils.except("Signature verification failed on the setup message.");
    }
    
    DHPubKey[] idPubkeys = message.getIdentities();
    DHPubKey myIdPubKey = idPubkeys[leafNum];
    
    DHPubKey myPrePubKey = message.getEphemeralKeys().get(leafNum);    
    
    // Utils.printTree(state.getTree());
    Utils.print("My ID pubkey from tree #%d: %s",leafNum, hexDump(myIdPubKey.getPubKeyBytes())); 
    Utils.print("My real pubkey: %s",hexDump(state.getIdentityKeyPair().getPubKeyBytes()));

    if (!Arrays.equals(myIdPubKey.getPubKeyBytes(), state.getIdentityKeyPair().getPubKeyBytes())) {
    	Utils.except("Identity pubkey mismatch for my leafnum!");
    }
    
    if (!Arrays.equals(myPrePubKey.getPubKeyBytes(), state.getMyPreKeyPair().getPubKeyBytes()) ) {
    	Utils.except("Message pre-key does not match my prekey!");
    }
    
    /*if (!Arrays.equals(state.getPreKeyFor(leafNum).getPubKeyBytes(), message.getEphemeralKeys().get(leafNum).getPubKeyBytes())) {
        Utils.except("Used the wrong ephemeral key.");
  	}*/
    
    SecretLeafNode leaf = new SecretLeafNode(
      DHKeyPair.fromBytes(
        Crypto.keyExchangeReceive(state.getIdentityKeyPair(), message.getIdentities()[0], state.getMyPreKeyPair(), message.getKeyExchangeKey()),
        false
      )
    );
    state.setTree(
      updateTreeWithSecretLeaf(
        message.getTree(),
        state.getPeerNum(),
        leaf
      )
    );
    state.setIdentities(
      message.getIdentities()
    );
    deriveStageKey(state);
    
  }

  public static AuthenticatedMessage updateKey(ARTState state) {
    SecretLeafNode newNode = new SecretLeafNode(DHKeyPair.generate(false));
    SecretNode newTree = updateTreeWithSecretLeaf(state.getTree(), state.getPeerNum(), newNode);
    state.setTree(newTree);
    UpdateMessage m = new UpdateMessage(
      state.getPeerNum(),
      pathNodeKeys(state.getTree(), state.getPeerNum())
    );
    byte[] serialisedUpdateMessage = m.serialise();
    byte[] mac = Crypto.hmacSha256(serialisedUpdateMessage, state.getStageKey());
    deriveStageKey(state);
    return new AuthenticatedMessage(serialisedUpdateMessage, mac);
  }

  public static void processUpdateMessage(ARTState state, AuthenticatedMessage message) {
    byte[] mac = Crypto.hmacSha256(message.getMessage(), state.getStageKey());
    if (!Arrays.equals(mac, message.getAuthenticator())) {
      Utils.except("MAC is incorrect for update message.");
    }
    UpdateMessage updateMessage = new UpdateMessage(message.getMessage());
    Node tree = state.getTree();
    tree = updateTreeWithPublicPath(tree, updateMessage.getLeafNum(), updateMessage.getPath(), 0);
    state.setTree((SecretNode) tree);
    deriveStageKey(state);
  }

  private static SecretNode createTree(DHKeyPair[] leaves) {
    int n = leaves.length;
    if (n == 0) {
      Utils.except("No leaves");
    }
    if (n == 1) {
      return new SecretLeafNode(leaves[0]);
    }
    int l = leftTreeSize(n);
    SecretNode left = createTree(Arrays.copyOfRange(leaves, 0, l));
    Node right = createTree(Arrays.copyOfRange(leaves, l, n));
    return new SecretParentNode(left, right);
  }

  private static void deriveStageKey(ARTState state) {
    state.setStageKey(
      Crypto.artKDF(
        state.getStageKey(),
        ((SecretParentNode)state.getTree()).getRawSecretKey(),
        state.getIdentities(),
        state.getTree()
      )
    );
  }

  private static SecretNode updateTreeWithSecretLeaf(Node tree, int i, SecretLeafNode newLeaf) {
    int l = leftTreeSize(tree.numLeaves());
    if (tree.numLeaves() == 1) {
      return newLeaf;
    }
    SecretParentNode result;
    ParentNode treeParent = (ParentNode)tree;

    if (i < l) {
      result = new SecretParentNode(
        updateTreeWithSecretLeaf(treeParent.getLeft(), i, newLeaf),
        treeParent.getRight()
      );
    } else {
      result = new SecretParentNode(
        treeParent.getLeft(),
        updateTreeWithSecretLeaf(treeParent.getRight(), i - l, newLeaf)
      );
    }
    return result;
  }

  private static Node updateTreeWithPublicPath(Node tree, int i, DHPubKey[] newPath, int pathIndex) {
    int l = leftTreeSize(tree.numLeaves());
    if (newPath.length - 1 == pathIndex) {
      return new PublicLeafNode(newPath[pathIndex]);
    }

    ParentNode result;
    ParentNode treeAsParent = (ParentNode) tree;
    Node newLeft;
    Node newRight;

    if (i < l) {
      newLeft = updateTreeWithPublicPath(treeAsParent.getLeft(), i, newPath, pathIndex + 1);
      newRight = treeAsParent.getRight();
    } else {
      newLeft = treeAsParent.getLeft();
      newRight = updateTreeWithPublicPath(treeAsParent.getRight(), i - l, newPath, pathIndex + 1);
    }

    if (newLeft instanceof SecretNode) {
      result = new SecretParentNode((SecretNode)newLeft, newRight);
    } else if (newRight instanceof SecretNode) {
      result = new SecretParentNode(newLeft, (SecretNode)newRight);
    } else {
      result = new PublicParentNode(
        newPath[pathIndex],
        newLeft,
        newRight
      );
    }

    if (!Arrays.equals(result.getPubKey().getPubKeyBytes(), newPath[pathIndex].getPubKeyBytes())) {
      Utils.printTree(result);
      Utils.except("Update operation inconsistent with provided path.");
    }

    return result;
  }

  protected static DHPubKey[] pathNodeKeys(Node tree, int i) {
    List<DHPubKey> keys = new ArrayList<DHPubKey>();

    while (tree.numLeaves() > 1) {
      int l = leftTreeSize(tree.numLeaves());
      ParentNode parentNode = (ParentNode) tree;
      keys.add(tree.getPubKey());
      if (i < l) {
        tree = parentNode.getLeft();
      } else {
        tree = parentNode.getRight();
        i -= l;
      }
    }
    keys.add(tree.getPubKey());
    return keys.toArray(new DHPubKey[] {});
  }

  private static int leftTreeSize(int numLeaves) {
    return (int)Math.pow(2, Math.ceil(Math.log(numLeaves) / Math.log(2)) - 1);
  }
  
  
  public static String hexDump(byte[] bytes) {
	  BigInteger bi = new BigInteger(bytes);
	  return bi.toString(16);
  }
}
