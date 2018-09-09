/**
 * Copyright (c) 2017-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
*/

package com.facebook.research.asynchronousratchetingtree;

import com.facebook.research.asynchronousratchetingtree.crypto.DHKeyPair;
import com.facebook.research.asynchronousratchetingtree.crypto.DHPubKey;
import com.facebook.research.asynchronousratchetingtree.crypto.SignedDHPubKey;

import java.util.HashMap;
import java.util.Map;

abstract public class GroupMessagingState {
  private int peerNum;
  private int peerCount;
  
  protected DHKeyPair identityKeyPair;
  private DHKeyPair myPreKeyPair;
  
  private Map<Integer, DHPubKey> preKeys = new HashMap<>();
  private Map<Integer, SignedDHPubKey> signedPreKeys = new HashMap<>();

  public GroupMessagingState(int peerNum, int peerCount) {
    this.peerNum = peerNum;
    this.peerCount = peerCount;
  }

  final public int getPeerNum() {
    return peerNum;
  }

  final public int getPeerCount() {
    return peerCount;
  }

  final public DHKeyPair getIdentityKeyPair() {
    return identityKeyPair;
  }

  final public DHPubKey getPreKeyFor(int peerNum) {
    if (!preKeys.containsKey(peerNum)) {
      throw new IllegalStateException("no pre key for peer #"+peerNum);
    }
    return preKeys.get(peerNum);
  }
  
  final public void setPreKeyFor(int peerNum, DHPubKey preKey) {
	  if ( peerNum == this.peerNum) {
		  throw new IllegalArgumentException("hands off my preKey!");
	  }
	  preKeys.put(peerNum, preKey);  
  }
  
  final public void setMyPreKeyPair(DHKeyPair myPreKeyPair) {
	  this.myPreKeyPair = myPreKeyPair;
	  preKeys.put(0, myPreKeyPair);
  }
  
  final public SignedDHPubKey getSignedDHPreKeyFor(int peerNum) {
	  throw new IllegalArgumentException("does not work this way!");
  }
  
  public DHKeyPair getMyPreKeyPair() {
	return myPreKeyPair;
  }
  
  public void setIdentityKeyPair(DHKeyPair idKeyPair) {
	  this.identityKeyPair = idKeyPair;
  }
   
  abstract public byte[] getKeyWithPeer(int n);
}
