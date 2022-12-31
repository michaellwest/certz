#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

#Depending on the operating system of the host machines(s) that will build or run the containers, the image specified in the FROM statement may need to be changed.
#For more information, please see https://aka.ms/containercompat

FROM mcr.microsoft.com/dotnet/runtime:7.0 AS base
WORKDIR /app

USER ContainerAdministrator

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["certz.csproj", "."]
RUN dotnet restore "./certz.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "certz.csproj" -c Debug -o /app/build

FROM build AS publish
RUN dotnet publish "certz.csproj" -c Debug -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
RUN dir
ENTRYPOINT ["dotnet", "certz.dll"]