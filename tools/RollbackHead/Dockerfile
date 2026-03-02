FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS build

WORKDIR /nethermind

COPY src/Nethermind/Nethermind.Core src/Nethermind/Nethermind.Core
COPY src/Nethermind/Nethermind.Config src/Nethermind/Nethermind.Config
COPY src/Nethermind/Nethermind.Logging src/Nethermind/Nethermind.Logging
COPY src/Nethermind/Nethermind.Db src/Nethermind/Nethermind.Db
COPY src/Nethermind/Nethermind.Serialization.Rlp src/Nethermind/Nethermind.Serialization.Rlp
COPY src/Nethermind/Nethermind.Trie src/Nethermind/Nethermind.Trie
COPY tools/RollbackHead tools/RollbackHead
COPY Directory.*.props ./
COPY global.json .
COPY nuget.config .

RUN dotnet publish tools/RollbackHead/RollbackHead.csproj -c Release -o /app --no-self-contained

FROM mcr.microsoft.com/dotnet/runtime:10.0-noble

WORKDIR /app
COPY --from=build /app .

ENTRYPOINT ["dotnet", "RollbackHead.dll"]
