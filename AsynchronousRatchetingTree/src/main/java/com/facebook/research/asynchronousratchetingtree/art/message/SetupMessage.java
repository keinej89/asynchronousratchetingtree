/**
 * Copyright (c) 2017-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
*/

package com.facebook.research.asynchronousratchetingtree.art.message;

import com.facebook.research.asynchronousratchetingtree.art.message.thrift.SetupMessageStruct;
import com.facebook.research.asynchronousratchetingtree.art.tree.Node;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.facebook.research.asynchronousratchetingtree.Utils;
import com.facebook.research.asynchronousratchetingtree.crypto.DHPubKey;


public class SetupMessage {
  private DHPubKey[] identities;
  private Map<Integer, DHPubKey> ephemeralKeys;
  private DHPubKey keyExchangeKey;
  private Node tree;

  public SetupMessage(DHPubKey[] identities, Map<Integer, DHPubKey> ephemeralKeys, DHPubKey keyExchangeKey, Node tree) {
    this.identities = identities;
    this.ephemeralKeys = ephemeralKeys;
    this.keyExchangeKey = keyExchangeKey;
    this.tree = tree;
  }

  public SetupMessage(byte[] thriftSerialised) {
    SetupMessageStruct struct = new SetupMessageStruct();
    Utils.deserialise(struct, thriftSerialised);

    identities = new DHPubKey[struct.getIdentities().size()];
    for (int i = 0; i < identities.length; i++) {
      try {
		identities[i] = DHPubKey.pubKey(
		    Base64.decode(struct.getIdentities().get(i))
		  );
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    }

    ephemeralKeys = new HashMap<>();
    for (int i = 1; i < identities.length; i++) {
      try {
		ephemeralKeys.put(
		    i,
		    DHPubKey.pubKey(
		      Base64.decode(struct.getEphemeralKeys().get(i))
		    )
		  );
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    }

    keyExchangeKey = DHPubKey.pubKey(struct.getKeyExchangeKey());
    tree = Node.fromThrift(struct.getTree());
  }

  public DHPubKey[] getIdentities() {
    return identities;
  }

  public Map<Integer, DHPubKey> getEphemeralKeys() {
    return ephemeralKeys;
  }

  public DHPubKey getKeyExchangeKey() {
    return keyExchangeKey;
  }

  public Node getTree() {
    return tree;
  }

  public byte[] serialise() {
    List<String> identities = new ArrayList<>();
    Map<Integer, String> ephemeralKeys = new HashMap<>();

    for (int i = 0; i < this.identities.length; i++) {
      identities.add(Base64.encodeBytes(this.identities[i].getPubKeyBytes()));
    }

    for (int i = 1; i < this.identities.length; i++) {
      ephemeralKeys.put(i, Base64.encodeBytes(this.ephemeralKeys.get(i).getPubKeyBytes()));
    }

    SetupMessageStruct struct = new SetupMessageStruct();
    struct.setIdentities(identities);
    struct.setEphemeralKeys(ephemeralKeys);
    struct.setKeyExchangeKey(keyExchangeKey.getPubKeyBytes());
    struct.setTree(Node.toThrift(tree));

    return Utils.serialise(struct);
  }
}
