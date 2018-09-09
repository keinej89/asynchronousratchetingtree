/**
 * Copyright (c) 2017-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
*/

package com.facebook.research.asynchronousratchetingtree.art.message;

import com.facebook.research.asynchronousratchetingtree.Utils;
import com.facebook.research.asynchronousratchetingtree.art.message.thrift.UpdateMessageStruct;
import com.facebook.research.asynchronousratchetingtree.crypto.DHPubKey;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class UpdateMessage {
  int leafNum;
  DHPubKey[] path;

  public UpdateMessage(int leafNum, DHPubKey[] path) {
    this.leafNum = leafNum;
    this.path = path;
  }

  public UpdateMessage(byte[] thriftSerialised) {
    UpdateMessageStruct struct = new UpdateMessageStruct();
    Utils.deserialise(struct, thriftSerialised);

    leafNum = struct.getLeafNum();
    path = new DHPubKey[struct.getPath().size()];
    for (int i = 0; i < path.length; i++) {
      try {
		path[i] = DHPubKey.pubKey(
		    Base64.decode(struct.getPath().get(i))
		  );
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    }
  }
  
  public int getLeafNum() {
    return leafNum;
  }

  public DHPubKey[] getPath() {
    return path;
  }

  public byte[] serialise() {
    List<String> path = new ArrayList<>();
    for (int i = 0; i < this.path.length; i++) {
      path.add(Base64.encodeBytes(this.path[i].getPubKeyBytes()));
    }
    UpdateMessageStruct struct = new UpdateMessageStruct();
    struct.setLeafNum(leafNum);
    struct.setPath(path);
    return Utils.serialise(struct);
  }
}
