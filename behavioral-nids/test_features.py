from packet_capture import PacketCapture
from feature_extractor import FeatureExtractor

capture = PacketCapture(interface="en0")
capture.start_capture(packet_count=30)

extractor = FeatureExtractor(window_size=1.0)
features = extractor.build_feature_vectors(capture.get_captured_packets())

print(f"\n{len(features)} vecteur(s) de features généré(s) :\n")
for f in features:
    print(f)