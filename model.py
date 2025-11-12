# Define the model
import torch.nn as nn
import torch.nn.functional as F

class NetModel(nn.Module):
  def __init__(self, features=128, hidden_nodes=50, classes=14):
    super().__init__()
    # Layers
    self.input = nn.Linear(features, hidden_nodes)
    self.linear1 = nn.Linear(hidden_nodes, hidden_nodes)
    self.dropout1 = nn.Dropout(0.2)
    self.linear2 = nn.Linear(hidden_nodes, hidden_nodes)
    self.output = nn.Linear(hidden_nodes, classes)

  def forward(self, x):
    x = self.input(x)
    x = F.relu(x)
    x = self.linear1(x)
    x = F.relu(x)
    x = self.dropout1(x)
    x = self.linear2(x)
    x = F.relu(x)
    x = self.output(x)
    # Don't need softmax here because it already is applied by CrossEntropyLoss
    return x