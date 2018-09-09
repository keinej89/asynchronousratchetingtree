import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import com.facebook.research.asynchronousratchetingtree.art.ART;
import com.facebook.research.asynchronousratchetingtree.art.ARTState;
import com.facebook.research.asynchronousratchetingtree.art.message.NodeTypeAdapter;
import com.facebook.research.asynchronousratchetingtree.art.tree.Node;
import com.facebook.research.asynchronousratchetingtree.crypto.DHKeyPair;
import com.facebook.research.asynchronousratchetingtree.crypto.DHPubKey;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class TestARTNodeSerialize {

	@Test
	public void testSerialize() {

		Gson gson = new GsonBuilder().registerTypeAdapter(Node.class, new NodeTypeAdapter()).create();
		ARTState blah = new ARTState(42, 42);

		DHKeyPair[] nodes = new DHKeyPair[10];
		DHPubKey[] peers = new DHPubKey[10];
		Map<Integer, DHPubKey> preKeys = new HashMap<>();

		for (int i = 0; i < 10; i++) {
			nodes[i] = DHKeyPair.generate(true);
			preKeys.put(i, nodes[i].getPubKey());
			peers[i] = nodes[i].getPubKey();
		}
		blah.setIdentityKeyPair(nodes[0]);
		blah.setMyPreKeyPair(nodes[0]);

		ART.setupGroup(blah, peers, preKeys);

		String json = gson.toJson(blah);

		System.out.println(json);

		ARTState state2 = gson.fromJson(json, ARTState.class);

		Node tree = state2.getTree();
		
		Assert.assertNotNull(tree);

	}

}
